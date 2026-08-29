from dataclasses import dataclass

from entities.camera_id import CameraId

@dataclass
class Record:
    camera_id: CameraId
    c_prime: bytes
    n: int
    nonce: bytes
    ciphertext: bytes