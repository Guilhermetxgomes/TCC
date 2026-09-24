import random

from crypto.puzzle import decrypt_all_records
from services.camera import Camera
from services.server import Server

# Plates circulating in the area, to simulate real traffic (not the target
# plate -- under busca_aberta the police don't even know which plate to
# look for).
PLATES_IN_CIRCULATION = [f"BRA{n:04d}" for n in range(200)]


def simulate_traffic(camera: Camera, server: Server, count: int) -> list:
    """
    Simulates a camera capturing `count` vehicles over a real period (for
    example, a whole afternoon on a busy avenue). Every plate is encrypted
    and handed straight to the real Server (Postgres) -- the camera has no
    idea, and doesn't need to know, that one of these captures will matter
    to the police later; it just sends and discards, like any other
    capture (see services/camera.py). Returns the records read back from
    the database, so busca_aberta below runs against what an
    investigation would actually query, not against Python objects still
    sitting in memory.
    """
    for _ in range(count):
        record = camera.encrypt_plate(random.choice(PLATES_IN_CIRCULATION))
        server.save(record)
    return server.get_records_by_camera_id(camera.id)


def run_busca_aberta(puzzle_level: int, capture_count: int, camera_id: int):
    """
    Real simulation of the busca_aberta case: the police are investigating
    a case where they only know the location and the time window -- not
    the plate (e.g. witnesses described the car, but nobody wrote the
    plate down). With no target plate, they have to decrypt EVERY capture
    from that window and cross-reference the result manually against the
    car description (`decrypt_all_records`, in crypto/puzzle.py).

    Unlike the scenario in main.py (which illustrates the puzzle cost over
    a single record), the cost here is measured over a volume of captures
    matching what a real camera would produce in a time window -- that is
    what makes busca_aberta expensive in practice: the cost scales with
    the number of records in the window, not just with N. Backed by the
    real Server/Postgres (see simulate_traffic), so this is the actual
    cost of querying and decrypting stored rows, not an in-memory
    approximation of it.
    """
    print(f"\n=== busca_aberta | N={puzzle_level} | captures in window={capture_count} ===")

    server = Server()
    camera = Camera(id=camera_id, location_id=101, puzzle_level=puzzle_level)
    captures = simulate_traffic(camera, server, capture_count)
    print(f"{len(captures)} encrypted captures stored in the database by camera {camera.id}.")

    result = decrypt_all_records(captures)

    average_attempts = result["total_puzzle_attempts"] / result["records_tested"]
    print(f"Records decrypted: {result['records_tested']}")
    print(f"Total puzzle attempts: {result['total_puzzle_attempts']}")
    print(f"Total time: {result['elapsed_seconds']:.4f} seconds")
    print(f"Average cost per record: {average_attempts:.1f} attempts")

    return result


if __name__ == "__main__":
    # Same N ladder used in main.py, now over a real volume of captures
    # per camera instead of a single isolated record. N=1_000_000 is left
    # out of the volume ladder: on a single record it already costs ~10s
    # (see main.py); running that for dozens of records in the same
    # script would make the simulation impractical to run -- the point
    # here is to show how cost scales with the VOLUME of captures, not to
    # repeat the extreme N that main.py already demonstrates.
    #
    # camera_id is drawn at random each run: the database persists across
    # executions (unlike the earlier in-memory version), so a fixed id
    # would silently accumulate rows from previous runs and inflate
    # "captures in window" over time.
    for puzzle_level in (100, 1_000, 10_000):
        run_busca_aberta(puzzle_level=puzzle_level, capture_count=50, camera_id=random.randint(10**6, 2**31 - 1))

    # With a larger N, we reduce the volume to keep the simulation
    # runnable, but the point still holds: cost per record grows with N.
    run_busca_aberta(puzzle_level=100_000, capture_count=10, camera_id=random.randint(10**6, 2**31 - 1))
