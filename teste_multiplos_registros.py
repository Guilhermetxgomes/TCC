import random
import statistics
import string

from services.camera import Camera
from services.server import Server
from crypto.puzzle import find_plate_in_records, decrypt_all_records

AWS_HOURLY_PRICE_USD = 0.1632  # m7g.xlarge (Graviton3, ARM), 4 vCPU / 16 GiB, us-east-1
# Link: https://aws.amazon.com/ec2/pricing/on-demand/ (17/08/2026)


def generate_random_plate() -> str:
    letters = "".join(random.choices(string.ascii_uppercase, k=3))
    digits = "".join(random.choices(string.digits, k=4))
    return f"{letters}{digits}"


def populate_window(camera: Camera, server: Server, window_size: int):
    generated_plates = []
    for _ in range(window_size):
        plate = generate_random_plate()
        generated_plates.append(plate)
        record = camera.encrypt_plate(plate)
        server.save(record)
    records = server.get_records_by_camera_id(camera.id)
    return generated_plates, records


def _summary(values: list) -> dict:
    return {
        "mean": statistics.mean(values),
        "min": min(values),
        "max": max(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def cost_usd(seconds: float) -> float:
    return (seconds / 3600.0) * AWS_HOURLY_PRICE_USD


def run_busca_fechada(puzzle_level: int, window_size: int, repetitions: int, camera_id_base: int) -> dict:
    server = Server()
    results = []
    for i in range(repetitions):
        camera = Camera(id=camera_id_base + i, location_id=1, puzzle_level=puzzle_level)
        plates, records = populate_window(camera, server, window_size)
        target_plate = random.choice(plates)
        results.append(find_plate_in_records(records, target_plate))

    elapsed = _summary([r["elapsed_seconds"] for r in results])
    return {
        "scenario": "busca_fechada",
        "puzzle_level": puzzle_level,
        "window_size": window_size,
        "repetitions": repetitions,
        "success_rate": sum(r["found"] for r in results) / repetitions,
        "elapsed_seconds": elapsed,
        "records_tested": _summary([r["records_tested"] for r in results]),
        "puzzle_attempts": _summary([r["total_puzzle_attempts"] for r in results]),
        "average_cost_usd": cost_usd(elapsed["mean"]),
        "max_cost_usd": cost_usd(elapsed["max"]),
    }


def run_busca_aberta(puzzle_level: int, window_size: int, repetitions: int, camera_id_base: int) -> dict:
    server = Server()
    results = []
    for i in range(repetitions):
        camera = Camera(id=camera_id_base + i, location_id=2, puzzle_level=puzzle_level)
        _plates, records = populate_window(camera, server, window_size)
        results.append(decrypt_all_records(records))

    elapsed = _summary([r["elapsed_seconds"] for r in results])
    return {
        "scenario": "busca_aberta",
        "puzzle_level": puzzle_level,
        "window_size": window_size,
        "repetitions": repetitions,
        "records_tested": window_size,
        "elapsed_seconds": elapsed,
        "puzzle_attempts": _summary([r["total_puzzle_attempts"] for r in results]),
        "average_cost_usd": cost_usd(elapsed["mean"]),
        "max_cost_usd": cost_usd(elapsed["max"]),
    }


def print_result(result: dict):
    elapsed = result["elapsed_seconds"]
    attempts = result["puzzle_attempts"]
    print(f"\n=== {result['scenario']} (N={result['puzzle_level']:,}, window={result['window_size']}) ===")
    print(f"Time (s): mean={elapsed['mean']:.4f} min={elapsed['min']:.4f} max={elapsed['max']:.4f} stdev={elapsed['stdev']:.4f}")
    print(f"Puzzle attempts: mean={attempts['mean']:.1f} min={attempts['min']} max={attempts['max']}")
    if isinstance(result["records_tested"], dict):
        r = result["records_tested"]
        print(f"Records tested: mean={r['mean']:.1f} min={r['min']} max={r['max']}")
        print(f"Success rate: {result['success_rate'] * 100:.1f}%")
    else:
        print(f"Records tested: {result['records_tested']} (fixed, entire window)")
    print(f"AWS cost (m7g.xlarge, ${AWS_HOURLY_PRICE_USD}/h): average=${result['average_cost_usd']:.8f} max=${result['max_cost_usd']:.8f}")


if __name__ == "__main__":
    WINDOW_SIZE = 50
    REPETITIONS = 5
    LEVELS = [1_000, 10_000, 100_000]

    all_results = []
    for n in LEVELS:
        base = n
        r1 = run_busca_fechada(n, WINDOW_SIZE, REPETITIONS, camera_id_base=base * 10 + 1000)
        r2 = run_busca_aberta(n, WINDOW_SIZE, REPETITIONS, camera_id_base=base * 10 + 2000)
        print_result(r1)
        print_result(r2)
        all_results.append((r1, r2))

    print(f"\n\n=== COMPARATIVE SUMMARY (window={WINDOW_SIZE} vehicles, {REPETITIONS} repetitions) ===")
    for r1, r2 in all_results:
        for r in (r1, r2):
            print(f"{r['puzzle_level']:>10,} | {r['scenario']:<14} | {r['elapsed_seconds']['mean']:>10.4f}s | "
                  f"${r['average_cost_usd']:.8f}")
