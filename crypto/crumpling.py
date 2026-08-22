import os
import random
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_nonce():
    return os.urandom(12)

def generate_c_prime():
    return os.urandom(32)

def generate_k(n):
    return random.randrange(0, n)

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