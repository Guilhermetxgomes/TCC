package ecc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
)

// SealKey cifra key com a PK mensal via X25519.
// Retorna encryptedKey, ephemeralPK e nonce para armazenamento.
func SealKey(key []byte, monthlyPK *ecdh.PublicKey) (encryptedKey, ephemeralPK, nonce []byte, err error) {
	curve := ecdh.X25519()
	ephSK, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	shared, err := ephSK.ECDH(monthlyPK)
	if err != nil {
		return
	}
	encKey := sha256.Sum256(shared)

	nonce = make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return
	}

	block, err := aes.NewCipher(encKey[:])
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	encryptedKey = gcm.Seal(nil, nonce, key, nil)
	ephemeralPK = ephSK.PublicKey().Bytes()
	return
}

// OpenKey decifra encryptedKey usando a SK mensal e a ephemeralPK da câmera.
func OpenKey(encryptedKey, ephemeralPK, nonce []byte, monthlySK *ecdh.PrivateKey) ([]byte, error) {
	curve := ecdh.X25519()
	ephPK, err := curve.NewPublicKey(ephemeralPK)
	if err != nil {
		return nil, err
	}

	shared, err := monthlySK.ECDH(ephPK)
	if err != nil {
		return nil, err
	}
	encKey := sha256.Sum256(shared)

	block, err := aes.NewCipher(encKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, encryptedKey, nil)
}
