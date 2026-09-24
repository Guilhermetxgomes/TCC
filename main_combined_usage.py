"""
Usage simulation combining busca_aberta and bolo_normal, the two
forward-looking cases from preBOLO.md.

One shared context, two police cases happening at the same time over the
same camera:

  Case 1 (bolo_normal): there is an active blocklist (e.g. a car reported
  stolen the day before). The police broadcast it once to every
  subscribed camera. Every time a camera captures a plate, it checks its
  own local blocklist in the clear and, on a hit, alerts the police right
  away -- no puzzle cost at all.

  Case 2 (busca_aberta): in parallel, a different case is being
  investigated (a hit-and-run on the same street) and the police DO NOT
  YET KNOW the plate -- only the approximate time window. For that case
  they later have to decrypt every capture from the window
  (`decrypt_all_records`), paying the full puzzle cost per record.

Both play out over the very same stream of captures, all sent to and
later queried from the real Server/Postgres, not held in memory: the
camera never knew, at capture time, that one of them would become a
busca_aberta target -- it only ever knew about the bolo_normal blocklist.
"""

import random
import time

from crypto.puzzle import decrypt_all_records
from entities.blocklist import Blocklist
from services.camera import Camera
from services.police import Police
from services.server import Server

PLATES_IN_CIRCULATION = [f"BRA{n:04d}" for n in range(200)]


def simulate_window(puzzle_level: int, capture_count: int, stolen_plate: str, hit_and_run_plate: str, camera_id: int):
    print(f"\n=== combined usage | N={puzzle_level} | captures in window={capture_count} ===")

    server = Server()
    police = Police()
    camera = Camera(id=camera_id, location_id=200, puzzle_level=puzzle_level, blocklist=Blocklist(), police=police)
    police.issue_bolo(stolen_plate, reason="stolen vehicle", ttl_seconds=24 * 3600)

    # the stolen plate (known in advance, on the blocklist) and the
    # hit-and-run plate (unknown until days later) pass by the camera at
    # different moments of the same window, mixed in with normal traffic
    plates_in_window = [random.choice(PLATES_IN_CIRCULATION) for _ in range(capture_count)]
    plates_in_window[capture_count // 3] = stolen_plate
    plates_in_window[2 * capture_count // 3] = hit_and_run_plate

    start = time.time()
    for plate in plates_in_window:
        record = camera.capture_plate(plate, timestamp="2026-09-21T18:30:00")["record"]
        server.save(record)
    capture_elapsed = time.time() - start

    print(
        f"{capture_count} captures processed in real time and sent to the server "
        f"(bolo_normal active the whole window)."
    )
    print(f"Direct alerts to the police during capture: {len(police.alerts_received)}")
    print(f"Capture flow time (blocklist check + send to server): {capture_elapsed:.4f} seconds")

    # days later, the hit-and-run case is opened -- the plate is unknown.
    # Queried back from the database, not from the Python list above,
    # which the camera already discarded.
    print("\n--- Days later: the hit-and-run case is opened, the plate is unknown ---")
    captures = server.get_records_by_camera_id(camera.id)
    open_search_result = decrypt_all_records(captures)
    print(f"Records decrypted in busca_aberta: {open_search_result['records_tested']}")
    print(f"Puzzle attempts in busca_aberta: {open_search_result['total_puzzle_attempts']}")
    print(f"busca_aberta time: {open_search_result['elapsed_seconds']:.4f} seconds")
    print(f"Hit-and-run plate was among the decrypted ones: {hit_and_run_plate in open_search_result['plates']}")

    print("\nWindow summary:")
    print(f"  - bolo_normal: {len(police.alerts_received)} direct alert(s), puzzle cost = 0")
    print(
        f"  - busca_aberta: {open_search_result['total_puzzle_attempts']} puzzle attempts "
        f"to solve a case with no known plate"
    )


if __name__ == "__main__":
    # camera_id is drawn at random each run: the database persists across
    # executions, so a fixed id would accumulate rows from previous runs.
    for puzzle_level in (100, 10_000):
        simulate_window(
            puzzle_level=puzzle_level,
            capture_count=40,
            stolen_plate="ROU4321",
            hit_and_run_plate="ATR0007",
            camera_id=random.randint(10**6, 2**31 - 1),
        )
