-- Amassamento por bloco (crypto/block_crumpling.py) e custódia para a Busca Total (crypto/escrow.py).
-- Server.ensure_schema() aplica o mesmo DDL (idempotente) em bancos já inicializados.

-- N acima de 2^31 - 1 não cabia em INTEGER (limitava o puzzle a 31 bits).
ALTER TABLE open_search_records ALTER COLUMN n TYPE BIGINT;

-- Rótulo do bloco a que o registro pertence (NULL no esquema original, por registro).
ALTER TABLE open_search_records ADD COLUMN IF NOT EXISTS block TEXT;

-- Cabeçalho público de cada bloco: um puzzle de tamanho t por (câmera, intervalo de tempo).
CREATE TABLE IF NOT EXISTS block_headers (
    header_id SERIAL PRIMARY KEY,
    run_id TEXT,
    camera_id INTEGER NOT NULL,
    block TEXT NOT NULL,
    c_prime TEXT NOT NULL,
    t BIGINT NOT NULL,
    check_nonce TEXT NOT NULL,
    check_tag TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_block_headers_run_camera_block
    ON block_headers (run_id, camera_id, block);

-- Chave de sessão de cada câmera cifrada para a chave pública do Comitê de Emergência do período.
CREATE TABLE IF NOT EXISTS session_key_wraps (
    wrap_id SERIAL PRIMARY KEY,
    run_id TEXT,
    camera_id INTEGER NOT NULL,
    period TEXT NOT NULL,
    session TEXT NOT NULL,
    r TEXT NOT NULL,
    nonce TEXT NOT NULL,
    wrapped TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_key_wraps_run_period_session
    ON session_key_wraps (run_id, period, session, camera_id);
