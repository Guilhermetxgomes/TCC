"""
Searches sized by real traffic (simulation/tolls.py).

For one toll plaza (one camera) and one time window, the number of records n is the real
number of vehicles that crossed it. The records themselves are generated here -- the
open data has counts, not plates -- encrypted, AD-bound and signed by a real Camera, and
the searches solve their puzzles for real with a small N; the cost is then extrapolated
to a realistic N with the time per attempt measured in this run.

Cost models compared on the same window (Seção "Volume por câmera"):
- per record:  n puzzles of size N;
- per block:   one puzzle of size N_B per hour of the window (N_B = 1000 x N, calibrated to
               cost the same as the per-record scheme at 1000 vehicles/hour).
"""
import random
import string
import time
from datetime import timedelta

from crypto.puzzle import solve_puzzle
from crypto.signing import verify_record
from services.camera import Camera
from simulation import costs
from simulation.tolls import TollCamera, TollData

MAX_REAL_RECORDS = 3000  # larger windows run on a sample of this size and are scaled up
BLOCK_REFERENCE_VOLUME = 1000  # vehicles/hour at which per-block and per-record cost the same


def _plate(rng: random.Random) -> str:
    return "".join(rng.choices(string.ascii_uppercase, k=3)) + rng.choice(string.digits) \
        + rng.choice(string.ascii_uppercase) + "".join(rng.choices(string.digits, k=2))


def window_counts(data: TollData, camera: TollCamera, day: str, start_hour: int, hours: int) -> list[int]:
    from datetime import datetime
    first = data.hour_index(datetime.fromisoformat(day)) + start_hour
    return [camera.hourly[h] if 0 <= h < len(camera.hourly) else 0 for h in range(first, first + hours)]


def run(data: TollData, camera: TollCamera, day: str, start_hour: int, hours: int, demo_n: int,
        realistic_n: int, seed: int = 0) -> dict:
    from datetime import datetime
    counts = window_counts(data, camera, day, start_hour, hours)
    n = sum(counts)
    if n == 0:
        raise ValueError("nenhum veículo passou nessa praça nessa janela")
    used = min(n, MAX_REAL_RECORDS)
    scale = n / used
    rng = random.Random(seed)

    # The camera captures `used` vehicles spread over the window, in order.
    device = Camera(id=camera.id, location_id=camera.id, puzzle_level=demo_n)
    begin = datetime.fromisoformat(day) + timedelta(hours=start_hour)
    plates = [_plate(rng) for _ in range(used)]
    started = time.perf_counter()
    stamps = sorted(begin + timedelta(seconds=rng.uniform(0, hours * 3600)) for _ in range(used))
    records = [device.encrypt_plate(p, s.isoformat()) for p, s in zip(plates, stamps)]
    capture_seconds = time.perf_counter() - started
    target_index = rng.randrange(used)
    target = plates[target_index]

    # Busca Fechada: open records in capture order until the target plate appears.
    # Busca Aberta: open every record of the window (plate unknown).
    fechada = {"records": 0, "attempts": 0, "seconds": 0.0}
    aberta = {"records": 0, "attempts": 0, "seconds": 0.0, "verify_seconds": 0.0}
    found_at = None
    for index, record in enumerate(records):
        t0 = time.perf_counter()
        ok = verify_record(record, device.public_key)
        aberta["verify_seconds"] += time.perf_counter() - t0
        if not ok:
            raise AssertionError("a freshly signed record must verify")
        result = solve_puzzle(record, sequential=True)
        aberta["records"] += 1
        aberta["attempts"] += result["attempts"]
        aberta["seconds"] += result["elapsed_seconds"]
        if found_at is None:
            fechada["records"] += 1
            fechada["attempts"] += result["attempts"]
            fechada["seconds"] += result["elapsed_seconds"]
            if result["plate"] == target:
                found_at = index
    per_attempt = aberta["seconds"] / aberta["attempts"]

    def extrapolate(records_opened: float, puzzle_size: int, puzzles: float = None) -> dict:
        count = records_opened if puzzles is None else puzzles
        attempts = count * costs.expected_attempts(puzzle_size)
        seconds = attempts * per_attempt
        return {"puzzles": count, "attempts": attempts, "seconds": seconds, "usd": costs.cost_usd(seconds)}

    block_n = BLOCK_REFERENCE_VOLUME * realistic_n
    expected_fechada = (n + 1) / 2
    camera_period = camera.total()
    network_year = sum(c.total() for c in data.cameras) * 8760 / data.hours
    return {
        "camera": {"id": camera.id, "name": camera.name, "lot": camera.lot},
        "window": {"day": day, "start_hour": start_hour, "hours": hours, "counts": counts},
        "n": n, "records_generated": used, "scale": scale,
        "demo_n": demo_n, "realistic_n": realistic_n, "block_n": block_n,
        "capture_us": capture_seconds / used * 1e6,
        "verify_us": aberta["verify_seconds"] / used * 1e6,
        "seconds_per_attempt": per_attempt,
        "target_position": target_index + 1,
        "measured": {"fechada": fechada, "aberta": {k: v for k, v in aberta.items() if k != "verify_seconds"}},
        "extrapolated": {
            # Fechada: expected (n+1)/2 records for a target anywhere in the window.
            "fechada": extrapolate(expected_fechada, realistic_n),
            "aberta": extrapolate(n, realistic_n),
            "bloco": extrapolate(0, block_n, puzzles=hours),
            "camera_periodo": extrapolate(camera_period, realistic_n),
            "rede_ano": extrapolate(network_year, realistic_n),
        },
        "camera_period_records": camera_period,
        "network_year_records": network_year,
    }
