package ecc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// SealKey cifra key com a PK mensal via X25519.
// O nonce AES-GCM é prefixado ao blob encryptedKey (primeiros 12 bytes),
// tornando-o auto-contido para armazenamento sem campo extra.
func SealKey(key []byte, monthlyPK *ecdh.PublicKey) (encryptedKey, ephemeralPK []byte, err error) {
	curve := ecdh.X25519()
	ephSK, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	shared, err := ephSK.ECDH(monthlyPK)
	if err != nil {
		return
	}
	aesKey := sha256.Sum256(shared)

	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return
	}

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	// encryptedKey = nonce || AES-GCM(key)
	ct := gcm.Seal(nil, nonce, key, nil)
	encryptedKey = append(nonce, ct...)
	ephemeralPK = ephSK.PublicKey().Bytes()
	return
}

// OpenKey decifra encryptedKey usando a SK mensal e a ephemeralPK da câmera.
// Espera o formato nonce||ciphertext produzido por SealKey.
func OpenKey(encryptedKey, ephemeralPK []byte, monthlySK *ecdh.PrivateKey) ([]byte, error) {
	if len(encryptedKey) < 12 {
		return nil, errors.New("ecc.OpenKey: encryptedKey muito curto")
	}
	nonce, ct := encryptedKey[:12], encryptedKey[12:]

	curve := ecdh.X25519()
	ephPK, err := curve.NewPublicKey(ephemeralPK)
	if err != nil {
		return nil, err
	}

	shared, err := monthlySK.ECDH(ephPK)
	if err != nil {
		return nil, err
	}
	aesKey := sha256.Sum256(shared)

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ct, nil)
}
