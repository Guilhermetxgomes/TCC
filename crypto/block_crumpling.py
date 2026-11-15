"""
Block crumpling: one puzzle per (camera, time slot) instead of one per record.

Motivation. In the original scheme the cost of opening a time window of a camera is
(records in the window) x N, so it grows linearly with the camera's traffic: the same
one-hour warrant costs 100x more on an avenue with 10 000 vehicles/hour than on a
street with 100. Here every capture of a slot (e.g. one hour) is encrypted under keys
derived from a single block key K_b = SHA-256(c'_b || k_b), with k_b drawn from [0, T).
Opening the slot costs one puzzle of size T, whatever the traffic was.

Records keep their own c' and their own (small or trivial) puzzle of size n:

    K_record = SHA-256(K_b || c'_record || k_record),   k_record in [0, n)

so n = 1 gives pure block crumpling and n > 1 gives a two-level scheme (a fixed cost
per slot plus a marginal cost per record), the layered composition described by
Wright and Varia. T = 1 would degenerate to the original scheme.

What this costs in privacy (discussed in docs/roteiro-cap4.md): solving one block
opens everyone who passed in that slot at no extra cost (if n = 1), the camera has to
keep K_b in memory for the whole slot, and a window that does not line up with the
slots pays for -- and exposes -- whole slots.
"""
import time
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag

from crypto.crumpling import decrypt, derive_key, encrypt, generate_c_prime, generate_k, generate_nonce
from crypto.puzzle import candidates
from entities.block_header import BlockHeader


def block_context(camera_id: int, block: str) -> bytes:
    return f"block|{camera_id}|{block}".encode()


def seal_block(camera_id: int, block: str, t: int,
               secret_for: Optional[Callable[[bytes], int]] = None) -> tuple[BlockHeader, bytes]:
    """
    Opens a new block on the camera: returns its public header and the block key, which
    the camera keeps in memory only until the slot ends. The block secret k is drawn at
    random unless `secret_for(c_prime)` is given (the escrow derives it from the session
    key, see crypto/escrow.py).
    """
    c_prime = generate_c_prime()
    k = generate_k(t) if secret_for is None else secret_for(c_prime)
    key = derive_key(c_prime, k)
    nonce = generate_nonce()
    tag = encrypt(b"", key, nonce, block_context(camera_id, block))
    return BlockHeader(camera_id=camera_id, block=block, c_prime=c_prime, t=t, check_nonce=nonce, check_tag=tag), key


def block_key_from_secret(header: BlockHeader, k: int) -> bytes:
    """Block key for a candidate k; raises InvalidTag when k is not the block's secret."""
    key = derive_key(header.c_prime, k)
    decrypt(header.check_tag, key, header.check_nonce, block_context(header.camera_id, header.block))
    return key


def solve_block(header: BlockHeader, sequential: bool = False) -> dict:
    """Brute-forces the block's k (same solver as crypto.puzzle.solve_puzzle, over [0, T))."""
    start_time = time.perf_counter()
    attempts = 0
    for k_candidate in candidates(header.t, sequential):
        attempts += 1
        try:
            key = block_key_from_secret(header, k_candidate)
        except InvalidTag:
            continue
        return {
            "key": key,
            "k_found": k_candidate,
            "attempts": attempts,
            "elapsed_seconds": time.perf_counter() - start_time,
        }
    raise ValueError("no k in [0, t) opens this block header")
