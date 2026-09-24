import random
import time

from crypto.puzzle import find_plate_in_records
from entities.blocklist import Blocklist
from services.camera import Camera
from services.police import Police
from services.server import Server

PLATES_IN_CIRCULATION = [f"BRA{n:04d}" for n in range(200)]


def run_bolo_normal(puzzle_level: int, capture_count: int, watched_plate: str, camera_ids: tuple):
    """
    Cost simulation of bolo_normal (forward-looking, preBOLO.md):

        1. Cameras are notified of the blocklist
        2. Cameras that see a blocklisted plate alert the police directly

    Two design decisions from the project discussion are demonstrated
    here:

    - Broadcast, not polling: the police hold a list of subscribed
      cameras (each one registers itself once, on construction -- see
      services/camera.py) and push the new plate to all of them in a
      single `Police.issue_bolo` call. No camera ever queries a central
      server per capture; every camera keeps its own local copy of the
      blocklist in memory, so the check at capture time never touches the
      network.

    - TTL on every entry: `issue_bolo` takes a `ttl_seconds`. Once it
      elapses, the plate is purged from each camera's local memory the
      next time that camera's blocklist is touched -- a camera never
      accumulates every BOLO ever issued.

    Unlike busca_aberta/busca_fechada, there is no cryptographic cost on
    the alert path at all: the blocklist check happens in the clear, at
    capture time, before the plate is even encrypted -- an O(1) dict
    lookup on the camera itself (see `Camera.capture_plate`), not a puzzle
    to solve.

    Cameras still encrypt and send every capture to the real Server
    (Postgres) as usual (alerted or not) -- that's the send-and-discard
    architecture -- so `puzzle_level` still exists; it is just never paid
    on this path. It is only paid later, if someone needs to run a
    busca_aberta or busca_fechada over these same stored captures, which
    is exactly what the comparison at the end of this function measures
    against the real database.
    """
    print(f"\n=== bolo_normal | N={puzzle_level} | captures in window={capture_count} ===")

    server = Server()
    police = Police()
    cameras = [
        Camera(id=camera_id, location_id=50 + (camera_id % 50), puzzle_level=puzzle_level, blocklist=Blocklist(), police=police)
        for camera_id in camera_ids
    ]

    # One broadcast event, issued once, reaches every subscribed camera --
    # this is the "cameras are notified of the blocklist" step.
    police.issue_bolo(watched_plate, reason="stolen vehicle", ttl_seconds=24 * 3600)
    for camera in cameras:
        assert camera.blocklist.contains(watched_plate), "broadcast should reach every subscribed camera"
    print(f"BOLO for '{watched_plate}' broadcast once, received by all {len(cameras)} subscribed cameras.")

    # The watched plate drives past only one of the three cameras,
    # somewhere in the middle of normal traffic. Only that camera fires an
    # alert, even though all three had the plate in their local blocklist.
    sighting_camera_index = 1
    traffic_per_camera = [[random.choice(PLATES_IN_CIRCULATION) for _ in range(capture_count)] for _ in cameras]
    traffic_per_camera[sighting_camera_index][capture_count // 2] = watched_plate

    start = time.time()
    for camera, plates in zip(cameras, traffic_per_camera):
        for plate in plates:
            record = camera.capture_plate(plate, timestamp="2026-09-21T14:00:00")["record"]
            server.save(record)
    elapsed_bolo_normal = time.time() - start

    # Read every camera's captures back from the database -- this is what
    # a busca_fechada/busca_aberta request would actually query, not the
    # in-memory Record objects the loop above already handed off and
    # discarded.
    captures = [record for camera in cameras for record in server.get_records_by_camera_id(camera.id)]

    print(f"{len(captures)} total captures stored in the database across {len(cameras)} cameras.")
    print(f"Direct alerts fired to the police: {len(police.alerts_received)}")
    print(
        f"Total time for the bolo_normal flow (blocklist check + capture + send to server): "
        f"{elapsed_bolo_normal:.4f} seconds"
    )

    # TTL check: with a very short TTL, the entry is gone from a camera's
    # local memory almost immediately, exactly as intended. No captures
    # involved here -- purely the local blocklist, so no server needed.
    short_lived_camera = Camera(
        id=camera_ids[0] + 900_000, location_id=999, puzzle_level=puzzle_level, blocklist=Blocklist(), police=Police()
    )
    police_for_ttl_demo = short_lived_camera.police
    police_for_ttl_demo.issue_bolo("TTL0001", reason="ttl demo", ttl_seconds=0.05)
    present_before_expiry = short_lived_camera.blocklist.contains("TTL0001")
    time.sleep(0.1)
    present_after_expiry = short_lived_camera.blocklist.contains("TTL0001")
    print(
        f"TTL demo: entry present right after broadcast = {present_before_expiry}, "
        f"present after the TTL elapsed = {present_after_expiry} (purged from local memory)."
    )

    # For comparison: what it would cost to reach the same result WITHOUT
    # bolo_normal, i.e. only after the fact, via busca_fechada (the police
    # already know which plate to look for) over the same stored captures
    # -- read back from the real database, not from memory. Only actually
    # run busca_fechada for N that finishes fast (up to 10_000); for a
    # larger N, the average cost per puzzle (~N/2 attempts) already makes
    # the point without running it for real and stalling the
    # demonstration.
    if puzzle_level <= 10_000:
        closed_search_result = find_plate_in_records(captures, watched_plate)
        print(
            f"\nFor comparison, finding plate '{watched_plate}' via busca_fechada after the fact "
            f"would cost {closed_search_result['total_puzzle_attempts']} puzzle attempts "
            f"in {closed_search_result['elapsed_seconds']:.4f} seconds -- "
            f"bolo_normal avoids paying that cost entirely when the plate is already known in advance."
        )
    else:
        estimated_cost = puzzle_level // 2
        print(
            f"\nFor comparison, with N={puzzle_level} each puzzle costs ~{estimated_cost} attempts on average "
            f"(N/2) to solve via busca_fechada after the fact -- expensive enough that it isn't worth actually "
            f"running in this demonstration. bolo_normal avoids paying that cost entirely."
        )

    return {
        "alerts": len(police.alerts_received),
        "elapsed_bolo_normal": elapsed_bolo_normal,
    }


if __name__ == "__main__":
    # camera_ids are drawn at random each run (three consecutive ids per
    # scenario): the database persists across executions, so fixed ids
    # would accumulate rows from previous runs and quietly change the
    # results.
    for puzzle_level in (100, 10_000, 1_000_000):
        base_camera_id = random.randint(10**6, 2**31 - 4)
        run_bolo_normal(
            puzzle_level=puzzle_level,
            capture_count=50,
            watched_plate="ROU4321",
            camera_ids=(base_camera_id, base_camera_id + 1, base_camera_id + 2),
        )
