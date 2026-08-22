import random
import time
from crypto.crumpling import derive_key, decrypt
from entities.record import Record


def solve_puzzle(record: Record) -> dict:
    start_time = time.time()

    attempts = 0
    while True:
        attempts += 1
        k_candidate = random.randrange(0, record.n)
        key_candidate = derive_key(record.c_prime, k_candidate)
        try:
            plaintext = decrypt(record.ciphertext, key_candidate, record.nonce, None)
        except Exception:
            continue

        elapsed = time.time() - start_time
        return {
            "success": True,
            "plate": plaintext.decode("utf-8"),
            "k_found": k_candidate,
            "attempts": attempts,
            "elapsed_seconds": elapsed,
        }

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