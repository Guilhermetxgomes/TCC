"""
Analytic cost model for the puzzle: the searches in the simulation run with a small
puzzle_level so they finish live, and these helpers extrapolate what the same search
would cost with a realistic puzzle_level.

Same assumptions as the chapter "Implementação e resultados experimentais" (Seção
"Busca dirigida e varredura em massa"), which favour whoever is decrypting:

- candidates for k are tested in sequence, without repetition: (N + 1) / 2 attempts
  per puzzle on average (the solver in crypto/puzzle.py draws with replacement, which
  costs N on average -- that is what the "real" attempts in the UI count);
- the cloud instance is used in full: each vCPU-second costs 1/4 of the m7g.xlarge
  hourly price, instead of charging the whole instance for one core.
"""

AWS_HOURLY_PRICE_USD = 0.1632  # m7g.xlarge (Graviton3, ARM), 4 vCPU / 16 GiB, us-east-1
# Link: https://aws.amazon.com/ec2/pricing/on-demand/ (17/08/2026)
AWS_VCPUS = 4

# Mass-surveillance reference scenario (working assumptions, not validated with CET data):
CITY_CAMERAS = 5000
CITY_RECORDS_PER_CAMERA_HOUR = 1000
CITY_HOURS = 24 * 365


def expected_attempts(puzzle_size: int) -> float:
    """Mean attempts to solve one puzzle of this size with the sequential strategy."""
    return (puzzle_size + 1) / 2


def cost_usd(core_seconds: float) -> float:
    return core_seconds / 3600.0 * AWS_HOURLY_PRICE_USD / AWS_VCPUS


def estimate(records_tested: int, measured_attempts: int, measured_seconds: float, realistic_n: int,
             blocks_solved: int = 0, realistic_t: int = 0, total_records: int = 0) -> dict:
    """
    Extrapolates a search that solved `records_tested` record puzzles (and, with block
    crumpling, `blocks_solved` block puzzles) to puzzles of size `realistic_n` (and
    `realistic_t`), using the time per attempt measured in the real run.

    With `total_records` (per-record crumpling only) it also prices the two mass
    surveillance references: opening every record of the simulated database, and
    opening a whole city for a year (CITY_* assumptions above).
    """
    seconds_per_attempt = measured_seconds / measured_attempts if measured_attempts else 0.0
    attempts = records_tested * expected_attempts(realistic_n) + blocks_solved * (
        expected_attempts(realistic_t) if blocks_solved else 0)
    seconds = attempts * seconds_per_attempt
    result = {
        "realistic_n": realistic_n,
        "realistic_t": realistic_t,
        "blocks_solved": blocks_solved,
        "seconds_per_attempt": seconds_per_attempt,
        "estimated_attempts": attempts,
        "estimated_seconds": seconds,
        "estimated_usd": cost_usd(seconds),
    }
    if total_records and not blocks_solved and realistic_n > 1:
        city_records = CITY_CAMERAS * CITY_RECORDS_PER_CAMERA_HOUR * CITY_HOURS
        for key, count in (("mass_sim", total_records), ("mass_city", city_records)):
            mass_seconds = count * expected_attempts(realistic_n) * seconds_per_attempt
            result[key + "_records"] = count
            result[key + "_seconds"] = mass_seconds
            result[key + "_usd"] = cost_usd(mass_seconds)
    return result
