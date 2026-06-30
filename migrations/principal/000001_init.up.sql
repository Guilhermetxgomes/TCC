-- Banco principal: registros ALPR para busca aberta e fechada

CREATE TABLE IF NOT EXISTS alpr_records (
    record_id       UUID        PRIMARY KEY,
    camera_id       TEXT        NOT NULL,
    captured_at     TIMESTAMPTZ NOT NULL,   -- truncado à hora
    region          TEXT        NOT NULL,
    key_month       TEXT        NOT NULL,   -- ex: "2026-06"
    plate_hmac      BYTEA       NOT NULL,   -- HMAC(placa, K_gov)

    -- Busca Aberta: crumpling por camera_id + captured_at
    open_ciphertext     BYTEA NOT NULL,
    open_nonce          BYTEA NOT NULL,
    open_entropy_bits   SMALLINT NOT NULL,
    open_puzzle_prefix  BYTEA NOT NULL,

    -- Busca Fechada: crumpling por HMAC(placa)
    closed_ciphertext     BYTEA NOT NULL,
    closed_nonce          BYTEA NOT NULL,
    closed_entropy_bits   SMALLINT NOT NULL,
    closed_puzzle_prefix  BYTEA NOT NULL,

    -- Busca Total: ECC com PK mensal (X25519)
    total_ciphertext    BYTEA NOT NULL,
    total_nonce         BYTEA NOT NULL,
    total_encrypted_key BYTEA NOT NULL,
    total_ephemeral_pk  BYTEA NOT NULL,

    -- Integridade
    signature   BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Busca Aberta: filtro por câmera + período
CREATE INDEX idx_alpr_camera_time ON alpr_records (camera_id, captured_at);

-- Busca Fechada: filtro por HMAC da placa
CREATE INDEX idx_alpr_plate_hmac ON alpr_records (plate_hmac);

-- Log de decodificação: imutável (append-only)
-- Toda decodificação autorizada gera uma entrada aqui.
CREATE TABLE IF NOT EXISTS decode_logs (
    log_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id   UUID        NOT NULL REFERENCES alpr_records(record_id),
    token_id    UUID        NOT NULL,
    search_type TEXT        NOT NULL CHECK (search_type IN ('open', 'closed', 'total')),
    decoded_by  TEXT        NOT NULL,   -- identificador do investigador
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_decode_logs_record ON decode_logs (record_id);
CREATE INDEX idx_decode_logs_token  ON decode_logs (token_id);

-- Tokens de autorização emitidos pelo juiz
CREATE TABLE IF NOT EXISTS authorization_tokens (
    token_id    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_data  BYTEA       NOT NULL,   -- token assinado pelo juiz (ECDSA)
    search_type TEXT        NOT NULL CHECK (search_type IN ('open', 'closed', 'total')),
    subject     TEXT        NOT NULL,   -- plate_hmac (hex) ou camera_id|date
    issued_by   TEXT        NOT NULL,   -- identificador do juiz
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tokens_subject ON authorization_tokens (subject);
