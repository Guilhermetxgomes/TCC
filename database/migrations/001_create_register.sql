CREATE TABLE records (
    record_id SERIAL PRIMARY KEY,
    camera_id INTEGER NOT NULL,
    c_prime TEXT NOT NULL,
    n INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);