-- Assinatura ECDSA (P-256) da câmera sobre o registro inteiro (crypto/signing.py).
-- O instante da captura (captured_at) já existia; agora ele é gerado pela câmera e entra,
-- com camera_id, no dado associado (AD) do AES-GCM, sem precisar de coluna nova.
-- Server.ensure_schema() aplica o mesmo DDL (idempotente) em bancos já inicializados.
ALTER TABLE open_search_records ADD COLUMN IF NOT EXISTS signature TEXT;
