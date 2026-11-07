"""
Analytic cost model for the puzzle: the searches in the simulation run with a small
puzzle_level so they finish live, and these helpers extrapolate what the same search
would cost with a realistic puzzle_level.
"""

AWS_HOURLY_PRICE_USD = 0.1632  # m7g.xlarge (Graviton3, ARM), 4 vCPU / 16 GiB, us-east-1
# Link: https://aws.amazon.com/ec2/pricing/on-demand/ (17/08/2026)

# crypto.puzzle.solve_puzzle draws k_candidate with replacement (random.randrange), so the
# number of attempts is geometric with mean N. (Benchmarks of an earlier, sequential
# solver gave N/2; the simulation follows the solver that is actually in the code.)
EXPECTED_ATTEMPTS_PER_N = 1.0


def cost_usd(seconds: float) -> float:
    return (seconds / 3600.0) * AWS_HOURLY_PRICE_USD


def estimate(records_tested: int, measured_attempts: int, measured_seconds: float, realistic_n: int) -> dict:
    """
    Extrapolates a search that solved `records_tested` puzzles to puzzles of size
    `realistic_n`, using the time per attempt measured in the real run.
    """
    seconds_per_attempt = measured_seconds / measured_attempts if measured_attempts else 0.0
    attempts = records_tested * realistic_n * EXPECTED_ATTEMPTS_PER_N
    seconds = attempts * seconds_per_attempt
    return {
        "realistic_n": realistic_n,
        "seconds_per_attempt": seconds_per_attempt,
        "estimated_attempts": attempts,
        "estimated_seconds": seconds,
        "estimated_usd": cost_usd(seconds),
    }
