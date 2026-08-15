import time
from crypto.crumpling import derive_key, decrypt
from entities.record import Record


def solve_puzzle(record: Record) -> dict:
    start_time = time.time()

    for k_candidate in range(record.n):
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
            "attempts": k_candidate + 1,
            "elapsed_seconds": elapsed,
        }

    elapsed = time.time() - start_time
    return {
        "success": False,
        "plate": None,
        "k_found": None,
        "attempts": record.n,
        "elapsed_seconds": elapsed,
    }