package governance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
)

// monthlyKeyFile é o formato JSON salvo em disco.
type monthlyKeyFile struct {
	KeyMonth   string `json:"key_month"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"` // AES-256-GCM(passphrase→SHA-256, SK raw bytes)
}

// SaveMonthlyKey cifra a SK X25519 com a passphrase e salva em path.
func SaveMonthlyKey(path string, sk *ecdh.PrivateKey, passphrase []byte) error {
	aesKey := deriveKey(passphrase)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("governance.SaveMonthlyKey: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("governance.SaveMonthlyKey: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("governance.SaveMonthlyKey nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, sk.Bytes(), nil)

	f := monthlyKeyFile{
		KeyMonth:   KeyMonth(),
		Nonce:      nonce,
		Ciphertext: ct,
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("governance.SaveMonthlyKey marshal: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadMonthlyKey lê e decifra a SK X25519 armazenada em path.
func LoadMonthlyKey(path string, passphrase []byte) (*ecdh.PrivateKey, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("governance.LoadMonthlyKey: %w", err)
	}

	var f monthlyKeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, "", fmt.Errorf("governance.LoadMonthlyKey unmarshal: %w", err)
	}

	aesKey := deriveKey(passphrase)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}

	skBytes, err := gcm.Open(nil, f.Nonce, f.Ciphertext, nil)
	if err != nil {
		return nil, "", fmt.Errorf("governance.LoadMonthlyKey decrypt: %w", err)
	}

	sk, err := ecdh.X25519().NewPrivateKey(skBytes)
	if err != nil {
		return nil, "", fmt.Errorf("governance.LoadMonthlyKey parse key: %w", err)
	}
	return sk, f.KeyMonth, nil
}

// deriveKey deriva uma chave AES-256 a partir de uma passphrase via SHA-256.
// Para um sistema de produção, usar Argon2id — para o protótipo, SHA-256 é suficiente.
func deriveKey(passphrase []byte) []byte {
	h := sha256.Sum256(passphrase)
	return h[:]
}
