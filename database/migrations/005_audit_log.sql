-- Log de decodificação do Servidor (services/audit_log.py): cadeia de hash assinada.
-- Cada linha é uma liberação de registros cifrados, uma recusa ou uma liberação da Busca Total.
-- Server.ensure_schema() aplica o mesmo DDL (idempotente) em bancos já inicializados.
CREATE TABLE IF NOT EXISTS audit_log (
    log_id SERIAL PRIMARY KEY,
    run_id TEXT,
    seq INTEGER NOT NULL,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    token_id TEXT,
    mode TEXT,
    operator_id TEXT,
    camera_id INTEGER,
    window_start TEXT,
    window_end TEXT,
    records INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    signature TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_log_run_seq ON audit_log (run_id, seq);
