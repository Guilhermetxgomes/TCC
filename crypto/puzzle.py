import random
import time
from typing import Iterator

from cryptography.exceptions import InvalidTag

from crypto.crumpling import derive_key, decrypt
from crypto.signing import record_ad
from entities.record import Record


# Random draws stop after this many times n attempts: the chance that a valid record is
# still unsolved by then is e^-64, so reaching it means no k opens the record (a record
# moved to another camera or instant fails the AD check for every k).
MAX_DRAWS_FACTOR = 64


def candidates(n: int, sequential: bool = False) -> Iterator[int]:
    """
    Order in which the solver tries k in [0, n).

    - sequential=False (default, the behaviour the simulation has always had): draws
      with replacement, so the number of attempts is geometric with mean n and no
      upper bound.
    - sequential=True: scans every value once, from a random starting point, so the
      mean is (n + 1) / 2 and the worst case is n. This is what a rational adversary
      does, hence the cost to assume in the security argument.

    The solver's randomness is not secret, so `random` is fine here (unlike in
    crypto.crumpling.generate_k).
    """
    if sequential:
        start = random.randrange(n)
        for offset in range(n):
            yield (start + offset) % n
    else:
        for _ in range(MAX_DRAWS_FACTOR * n):
            yield random.randrange(n)


def open_record(record: Record, k: int, key_prefix: bytes = b"") -> str:
    """
    Decrypts a record given its puzzle solution k. Raises InvalidTag if k is wrong -- or if
    camera_id / captured_at are not the ones the camera bound into the associated data.
    """
    key = derive_key(key_prefix + record.c_prime, k)
    return decrypt(record.ciphertext, key, record.nonce, record_ad(record.camera_id, record.captured_at)).decode("utf-8")


def solve_puzzle(record: Record, key_prefix: bytes = b"", sequential: bool = False) -> dict:
    """
    Brute-forces the record's k. `key_prefix` is the block key when the record belongs
    to a crumpled block (crypto/block_crumpling.py); empty in the original scheme.
    """
    start_time = time.perf_counter()

    attempts = 0
    for k_candidate in candidates(record.n, sequential):
        attempts += 1
        try:
            plate = open_record(record, k_candidate, key_prefix)
        except InvalidTag:
            continue

        return {
            "success": True,
            "plate": plate,
            "k_found": k_candidate,
            "attempts": attempts,
            "elapsed_seconds": time.perf_counter() - start_time,
        }
    raise ValueError("no k in [0, n) opens this record (wrong block key, or camera/instant/ciphertext altered)")

def find_plate_in_records(records: list[Record], target_plate: str) -> dict:
    """
    In case the cop already knows the plate of the car involved in the situation
    """
    start_time = time.time()
    total_attempts = 0

    for index, record in enumerate(records):
        result = solve_puzzle(record)
        total_attempts += result["attempts"]
        if result["plate"] == target_plate:
            return {
                "found": True,
                "records_tested": index + 1,
                "total_puzzle_attempts": total_attempts,
                "elapsed_seconds": time.time() - start_time,
            }

    return {
        "found": False,
        "records_tested": len(records),
        "total_puzzle_attempts": total_attempts,
        "elapsed_seconds": time.time() - start_time,
    }


def decrypt_all_records(records: list[Record]) -> dict:
    """
    In case the cop does not know the plate of the car involved in the situation, only the time and model references
    about the car, so it's necessary to decrypt all the plates from a camera in a specific time period
    """
    start_time = time.time()
    total_attempts = 0
    plates = []

    for record in records:
        result = solve_puzzle(record)
        total_attempts += result["attempts"]
        plates.append(result["plate"])

    return {
        "records_tested": len(records),
        "total_puzzle_attempts": total_attempts,
        "elapsed_seconds": time.time() - start_time,
        "plates": plates,
    }
