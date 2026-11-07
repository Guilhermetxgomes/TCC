-- Separa os registros gerados por cada execução da simulação web.
-- Registros dos scripts main_*.py continuam com run_id NULL.
-- Server.ensure_schema() aplica o mesmo DDL (idempotente) para bancos já inicializados,
-- onde esta migration não roda sozinha (docker-entrypoint-initdb.d só roda com volume vazio).
ALTER TABLE open_search_records ADD COLUMN IF NOT EXISTS run_id TEXT;

CREATE INDEX IF NOT EXISTS idx_open_search_records_run_camera_time
    ON open_search_records (run_id, camera_id, captured_at);
