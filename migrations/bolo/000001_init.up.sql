-- Banco BOLO: registros exclusivos de placas na lista negra

CREATE TABLE IF NOT EXISTS bolo_records (
    record_id   UUID        PRIMARY KEY,
    plate_hmac  BYTEA       NOT NULL,   -- HMAC(placa, K_gov)
    captured_at TIMESTAMPTZ NOT NULL,
    region      TEXT        NOT NULL,

    -- Crumpling com k_0' independente do banco principal
    ciphertext      BYTEA    NOT NULL,
    nonce           BYTEA    NOT NULL,
    entropy_bits    SMALLINT NOT NULL,
    puzzle_prefix   BYTEA    NOT NULL,

    -- Integridade
    signature   BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bolo_plate_hmac  ON bolo_records (plate_hmac);
CREATE INDEX idx_bolo_captured_at ON bolo_records (captured_at);

-- Log de decodificação do banco BOLO (separado do log principal)
CREATE TABLE IF NOT EXISTS bolo_decode_logs (
    log_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id   UUID        NOT NULL REFERENCES bolo_records(record_id),
    token_id    UUID        NOT NULL,
    decoded_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
