from dataclasses import dataclass


@dataclass
class BlockHeader:
    """
    Public header of one crumpled block: every capture of one camera in one time slot
    (e.g. one hour) shares a single puzzle of size `t`, instead of (or on top of) one
    puzzle per record. See crypto/block_crumpling.py.

    `check_tag` is AES-256-GCM(block_key, check_nonce, b"") bound to (camera_id, block):
    it lets whoever is brute-forcing the block recognise the right key without needing
    any record of the block.
    """
    camera_id: int
    block: str  # "<time slot>#<sequence>", e.g. "2026-01-01T08#0"
    c_prime: bytes
    t: int
    check_nonce: bytes
    check_tag: bytes
