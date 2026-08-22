from dataclasses import dataclass

@dataclass
class Record:
    camera_id: int
    c_prime: bytes
    n: int
    nonce: bytes
    ciphertext: bytes