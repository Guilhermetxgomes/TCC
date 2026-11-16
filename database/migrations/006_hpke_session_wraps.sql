-- Custódia da Busca Total com bibliotecas (HPKE X25519 do pacote cryptography + Shamir da PyCryptodome):
-- o encapsulamento da chave de sessão passa a ser uma única saída HPKE (chave encapsulada || texto cifrado),
-- guardada em `wrapped`; as colunas do ElGamal próprio (r, nonce) deixam de existir.
-- Server.ensure_schema() aplica o mesmo DDL (idempotente) em bancos já inicializados.
ALTER TABLE session_key_wraps DROP COLUMN IF EXISTS r;
ALTER TABLE session_key_wraps DROP COLUMN IF EXISTS nonce;
