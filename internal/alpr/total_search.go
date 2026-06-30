package alpr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/json"
	"fmt"

	"github.com/Guilhermetxgomes/TCC/internal/crypto/ecc"
)

// DecryptTotal decifra o TotalPayload de um ALPRRecord usando a SK mensal reconstruída.
func DecryptTotal(r ALPRRecord, monthlySK *ecdh.PrivateKey) (ALPRPlaintext, error) {
	k, err := ecc.OpenKey(r.TotalPayload.EncryptedKey, r.TotalPayload.EphemeralPK, monthlySK)
	if err != nil {
		return ALPRPlaintext{}, fmt.Errorf("DecryptTotal: recuperar chave efêmera: %w", err)
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return ALPRPlaintext{}, fmt.Errorf("DecryptTotal: NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ALPRPlaintext{}, err
	}

	plainJSON, err := gcm.Open(nil, r.TotalPayload.Nonce, r.TotalPayload.Ciphertext, nil)
	if err != nil {
		return ALPRPlaintext{}, fmt.Errorf("DecryptTotal: AES-GCM: %w", err)
	}

	var p ALPRPlaintext
	if err := json.Unmarshal(plainJSON, &p); err != nil {
		return ALPRPlaintext{}, fmt.Errorf("DecryptTotal: unmarshal: %w", err)
	}
	return p, nil
}
