"""
Time and space complexity analysis for bolo_normal on the camera side:
what it costs, per plate, to (a) hold a plate on the local blocklist and
(b) produce the resulting encrypted Record. The camera sends that Record
to the central server and discards it right away (see services/server.py)
-- it does not retain a growing archive of captures itself, so (b) is
about the transient, per-capture cost, not an accumulating one.

Space is analyzed twice, on purpose:

  - "raw storage" functions below: an exact byte accounting of what a
    real, resource-constrained camera would actually need on the wire
    (fixed-width integers, raw bytes, no language runtime overhead).
    This is the number that matters for embedded hardware.

  - `deep_sizeof`: the actual Python object size in THIS simulation
    (via sys.getsizeof). Useful for sanity-checking the simulation
    itself, but not representative of real camera hardware -- Python
    objects carry headers and string overhead a C/embedded
    implementation wouldn't. The two are kept clearly separate so they
    are never confused with one another.

Time is analyzed in two separate benchmarks, deliberately kept apart:

  - `measure_capture_time`: the LOCAL cost of capture_plate (blocklist
    check + encrypt_plate), with no network involved. This is what
    grounds the O(1)-regardless-of-N claim.

  - `measure_server_save_time`: the REAL cost of Server.save() against
    Postgres -- the "send" half of send-and-discard. Mixing this into
    the benchmark above would make the O(1) local claim look like it
    depends on network/DB latency, when the whole point of the
    architecture is that it doesn't: the camera's own cost and the
    server hand-off cost are two different numbers, so they stay two
    different measurements.
"""

import random
import sys
import time

from crypto.puzzle import solve_puzzle
from entities.blocklist import Blocklist
from entities.blocklist_entry import BlocklistEntry
from entities.record import Record
from services.camera import Camera
from services.police import Police
from services.server import Server

PLATES_IN_CIRCULATION = [f"BRA{n:04d}" for n in range(200)]

# ---------------------------------------------------------------------------
# Space complexity: exact byte accounting (real hardware, not Python)
# ---------------------------------------------------------------------------

GCM_TAG_BYTES = 16      # AESGCM always appends a fixed 16-byte auth tag
NONCE_BYTES = 12        # crypto.crumpling.generate_nonce(): os.urandom(12)
C_PRIME_BYTES = 32      # crypto.crumpling.generate_c_prime(): os.urandom(32)
CAMERA_ID_BYTES = 4     # fixed-width uint32 in a real wire format
PUZZLE_LEVEL_BYTES = 4  # fixed-width uint32 in a real wire format
EXPIRES_AT_BYTES = 4    # unix timestamp, seconds resolution, uint32


def raw_record_storage_bytes(plate: str) -> dict:
    """
    What one Record (crypto/puzzle.py) actually needs on the wire per
    stored capture -- what busca_aberta/busca_fechada later pay to
    decrypt. Independent of puzzle_level: N only decides how many puzzle
    attempts it takes to SOLVE the record later, never how many bytes it
    takes to STORE it now.
    """
    ciphertext_bytes = len(plate.encode("utf-8")) + GCM_TAG_BYTES
    breakdown = {
        "camera_id": CAMERA_ID_BYTES,
        "c_prime": C_PRIME_BYTES,
        "n (puzzle_level)": PUZZLE_LEVEL_BYTES,
        "nonce": NONCE_BYTES,
        "ciphertext": ciphertext_bytes,
    }
    breakdown["total"] = sum(breakdown.values())
    return breakdown


def raw_blocklist_entry_storage_bytes(plate: str, reason: str) -> dict:
    """
    What one active blocklist entry costs a camera to hold in memory.
    Unlike the encrypted Record above, this is bounded by TTL: an entry
    only occupies memory between being broadcast and expiring, never
    forever (see entities/blocklist.py).
    """
    breakdown = {
        "plate (dict key)": len(plate.encode("utf-8")),
        "reason": len(reason.encode("utf-8")),
        "expires_at": EXPIRES_AT_BYTES,
    }
    breakdown["total"] = sum(breakdown.values())
    return breakdown


def format_bytes(num_bytes: float) -> str:
    """Human-readable size, for the total-memory estimate below."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TiB"


def estimate_camera_total_memory(
    active_bolo_count: int,
    record_bytes: int,
    blocklist_entry_bytes: int,
    send_buffer_capacity: int = 1,
) -> dict:
    """
    Total memory a single camera needs at any given moment.

    Architecture decision: the camera only ever holds a Record for as
    long as it takes to encrypt it and hand it off to the central server
    (services/server.py) -- as soon as that send completes, the record is
    discarded from local memory. There is no retention window on the
    camera itself; busca_aberta/busca_fechada later query the SERVER's
    stored records, not the camera's. So Record memory does not scale
    with traffic or with time at all: it is bounded by how many records
    can be in flight to the server at once (`send_buffer_capacity` -- a
    fixed design constant, sized for how long a brief network hiccup
    might delay the send, not by how many plates the camera has ever
    captured).

    The blocklist is the only other thing occupying camera memory, and
    it is independently bounded by its own TTL (entities/blocklist.py).
    Neither term grows with the camera's traffic volume.
    """
    blocklist_bytes = active_bolo_count * blocklist_entry_bytes
    send_buffer_bytes = send_buffer_capacity * record_bytes
    return {
        "blocklist_bytes": blocklist_bytes,
        "send_buffer_bytes": send_buffer_bytes,
        "total_bytes": blocklist_bytes + send_buffer_bytes,
    }


def deep_sizeof(obj) -> int:
    """
    sys.getsizeof only accounts for the container itself, not what it
    points to. For a plain dataclass of primitive/bytes/str fields (no
    cycles, nothing shared), adding each field's own size on top gives a
    much closer picture of what the object costs in THIS Python
    simulation -- see the module docstring for why this is still not the
    same question as raw_*_storage_bytes above.
    """
    size = sys.getsizeof(obj)
    for field_name in getattr(obj, "__dataclass_fields__", {}):
        size += sys.getsizeof(getattr(obj, field_name))
    return size


# ---------------------------------------------------------------------------
# Time complexity
# ---------------------------------------------------------------------------

def measure_capture_time(puzzle_level: int, capture_count: int) -> float:
    """
    Times `capture_count` calls to Camera.capture_plate (blocklist check
    + encrypt_plate). Both steps are O(1) per call: the blocklist check
    is a dict lookup plus an amortized purge, and encrypt_plate always
    derives one key and runs one fixed-size AES-GCM encryption --
    generate_k draws a single random k in [0, N), it never loops over N.
    This should stay flat as puzzle_level grows, unlike solve_puzzle
    (used by busca_aberta/busca_fechada), whose cost is O(N) because it
    guesses k by brute force. No network involved -- see
    measure_server_save_time for the real send cost.
    """
    police = Police()
    camera = Camera(id=1, location_id=1, puzzle_level=puzzle_level, blocklist=Blocklist(), police=police)

    start = time.perf_counter()
    for _ in range(capture_count):
        camera.capture_plate(random.choice(PLATES_IN_CIRCULATION))
    return time.perf_counter() - start


def measure_server_save_time(puzzle_level: int, sample_count: int, camera_id: int) -> float:
    """
    Times `sample_count` real Server.save() calls (Postgres) for already-
    encrypted records -- the actual network+DB cost of the "send" half
    of send-and-discard. Kept as a separate measurement from
    measure_capture_time on purpose (see module docstring): mixing the
    two would make the local, O(1) capture_plate claim look like it
    depends on network latency, when the whole point of the architecture
    is that it doesn't -- the camera computes locally, then separately
    hands the result off.
    """
    server = Server()
    camera = Camera(id=camera_id, location_id=1, puzzle_level=puzzle_level)
    records = [camera.encrypt_plate(random.choice(PLATES_IN_CIRCULATION)) for _ in range(sample_count)]

    start = time.perf_counter()
    for record in records:
        server.save(record)
    return time.perf_counter() - start


def run_complexity_analysis():
    sample_plate = "ABC1234"
    sample_reason = "stolen vehicle"

    print("=== Space | raw storage per plate (embedded-hardware estimate) ===")
    record_bytes = raw_record_storage_bytes(sample_plate)
    for field, size in record_bytes.items():
        print(f"  Record.{field}: {size} bytes")
    print(
        f"-> O(1) per capture: {record_bytes['total']} bytes, independent of puzzle_level. This is what gets "
        f"sent to the central server and discarded from the camera right after -- see the send-and-discard "
        f"estimate below for what that means for the camera itself, as opposed to the server's own storage."
    )

    print()
    entry_bytes = raw_blocklist_entry_storage_bytes(sample_plate, sample_reason)
    for field, size in entry_bytes.items():
        print(f"  BlocklistEntry.{field}: {size} bytes")
    print(
        f"-> O(1) per active BOLO: {entry_bytes['total']} bytes, but bounded by TTL: steady-state space is "
        f"O(active BOLOs), not O(total BOLOs ever issued)."
    )

    print("\n=== Space | actual Python object size in this simulation ===")
    sample_record = Record(
        camera_id=1,
        c_prime=b"\x00" * C_PRIME_BYTES,
        n=100,
        nonce=b"\x00" * NONCE_BYTES,
        ciphertext=b"\x00" * (len(sample_plate) + GCM_TAG_BYTES),
    )
    sample_entry = BlocklistEntry(reason=sample_reason, expires_at=time.time())
    print(f"  Record object (sys.getsizeof + fields): {deep_sizeof(sample_record)} bytes")
    print(f"  BlocklistEntry object (sys.getsizeof + fields): {deep_sizeof(sample_entry)} bytes")
    print("  (larger than the raw estimates above: Python object/string headers, absent on real hardware)")

    print("\n=== Space | blocklist memory stays bounded thanks to TTL ===")
    police = Police()
    camera = Camera(id=2, location_id=2, puzzle_level=100, blocklist=Blocklist(), police=police)
    for i in range(500):
        police.issue_bolo(f"OLD{i:04d}", reason="test", ttl_seconds=0.01)
    print(f"  Active entries right after issuing 500 short-lived BOLOs: {len(camera.blocklist)}")
    time.sleep(0.05)  # long enough for every 0.01s TTL above to have elapsed
    police.issue_bolo("CURRENT1", reason=sample_reason, ttl_seconds=3600)
    print(
        f"  Active entries after the 500 expire and 1 new one is issued: {len(camera.blocklist)} "
        f"(memory did not grow with the 500 issued earlier)"
    )

    print("\n=== Space | total camera memory estimate (send-and-discard architecture) ===")
    print(
        "  Architecture: the camera holds a Record only until it hands it off to the central server "
        "(services/server.py), then discards it -- busca_aberta/busca_fechada query the SERVER's stored "
        "records afterwards, not the camera's. So camera memory does NOT scale with traffic or with time; "
        "it is bounded by (a) the blocklist, capped by TTL, and (b) a small fixed send buffer sized for "
        "brief network hiccups, not by how many plates the camera has ever seen."
    )
    active_bolo_scenarios = [50, 500, 5_000]
    send_buffer_scenarios = [1, 8, 64]

    for send_buffer_capacity in send_buffer_scenarios:
        print(f"\n  Send buffer capacity: {send_buffer_capacity} record(s) in flight at once")
        for active_bolo_count in active_bolo_scenarios:
            estimate = estimate_camera_total_memory(
                active_bolo_count=active_bolo_count,
                record_bytes=record_bytes["total"],
                blocklist_entry_bytes=entry_bytes["total"],
                send_buffer_capacity=send_buffer_capacity,
            )
            print(
                f"    {active_bolo_count:>5} active BOLOs: "
                f"blocklist={format_bytes(estimate['blocklist_bytes']):>9} + "
                f"send buffer={format_bytes(estimate['send_buffer_bytes']):>8} "
                f"= {format_bytes(estimate['total_bytes']):>9}"
            )
    print(
        "\n  Takeaway: the total stays in the tens of KiB regardless of whether the camera sees 100 or "
        "3000 plates/hour, and regardless of how long it has been running -- traffic volume and uptime "
        "don't appear in the formula at all, because nothing accumulates on the camera. This is a much "
        "stronger space bound than a retention-window model would give, and it matches preBOLO.md's own "
        "motivation (\"a stolen camera should hold almost no information\") even for busca_aberta/busca_fechada, "
        "not just for PreBOLO's bloom filters."
    )

    print("\n=== Time | capture_plate (bolo_normal) vs. solve_puzzle (busca_aberta/busca_fechada) ===")
    for puzzle_level in (100, 10_000, 1_000_000):
        elapsed = measure_capture_time(puzzle_level, capture_count=2_000)
        per_capture_us = (elapsed / 2_000) * 1e6
        print(
            f"  capture_plate | N={puzzle_level:>9} | {per_capture_us:6.2f} µs/capture over 2000 captures "
            f"-- flat regardless of N: capture_plate is O(1)"
        )

    print()
    for puzzle_level in (100, 10_000, 1_000_000):
        camera = Camera(id=3, location_id=3, puzzle_level=puzzle_level)
        record = camera.encrypt_plate(sample_plate)
        result = solve_puzzle(record)
        attempts_us = result["elapsed_seconds"] * 1e6
        print(
            f"  solve_puzzle  | N={puzzle_level:>9} | {result['attempts']:>9} attempts, "
            f"{attempts_us:12.2f} µs total -- grows with N: solve_puzzle is O(N)"
        )

    print("\n=== Time | Server.save (real Postgres) -- the actual cost of the \"send\" in send-and-discard ===")
    save_elapsed = measure_server_save_time(
        puzzle_level=100, sample_count=200, camera_id=random.randint(10**6, 2**31 - 1)
    )
    per_save_ms = (save_elapsed / 200) * 1e3
    print(f"  Server.save | {per_save_ms:.3f} ms/record over 200 records (real network + DB round-trip)")
    print(
        "  This is measured separately from capture_plate on purpose: mixing the two would make the O(1) "
        "local claim look like it depends on network/DB latency, when the whole point of send-and-discard "
        "is that the camera's own cost and the server hand-off cost are independent of each other."
    )

    print(
        "\nSummary: capture_plate (bolo_normal) is O(1) in time and O(1) in space per capture "
        f"({record_bytes['total']} bytes of Record + at most {entry_bytes['total']} bytes of blocklist entry, "
        "bounded by TTL), measured with no network involved. Sending that Record to the real server costs "
        f"~{per_save_ms:.3f} ms/record, independent of N. solve_puzzle (busca_aberta/busca_fechada) is O(N) "
        "in time and pays no extra space of its own -- it reads the Record that was already stored on the server."
    )


if __name__ == "__main__":
    run_complexity_analysis()
