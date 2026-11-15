import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_nonce():
    return os.urandom(12)

def generate_c_prime():
    return os.urandom(32)

def generate_k(n):
    # k is THE secret of the puzzle, so it must come from the OS CSPRNG. `random` is a
    # Mersenne Twister: its state can be rebuilt from enough outputs, and whoever solved
    # some puzzles of a camera could then predict every other k of that camera for free.
    return secrets.randbelow(n)

def derive_key(c_prime, k):
    k_bytes = k.to_bytes((k.bit_length() + 7) // 8 or 1, byteorder="big")
    h = hashlib.new('sha256')
    h.update(c_prime + k_bytes)
    return h.digest()

def encrypt(data, key, nonce, associated_data):
    cipher = AESGCM(key)
    return cipher.encrypt(nonce, data, associated_data)

def decrypt(data, key, nonce, associated_data):
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, data, associated_data)