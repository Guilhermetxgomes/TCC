package crumpling

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultEntropyBits = 14
	argonMemory        = 8 * 1024 // 8MB
	argonTime          = 1
	argonThreads       = 1
	argonKeyLen        = 32
)

// Seal cifra plaintext com o mecanismo de crumpling.
// ad é o Associated Data que vincula o ciphertext ao contexto (placa ou camera|time).
func Seal(plaintext, ad []byte) (ciphertext, nonce, puzzlePrefix, k0 []byte, err error) {
	k0 = make([]byte, 32)
	if _, err = rand.Read(k0); err != nil {
		return
	}
	nonce = make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return
	}

	kCcz := deriveKey(k0, ad)

	block, err := aes.NewCipher(kCcz)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, ad)

	suffixBytes := (DefaultEntropyBits + 7) / 8
	puzzlePrefix = k0[:len(k0)-suffixBytes]
	return
}

// Open recupera o plaintext brute-forçando o sufixo de k0.
func Open(ciphertext, nonce, puzzlePrefix, ad []byte, entropyBits uint8) ([]byte, error) {
	suffixBytes := (int(entropyBits) + 7) / 8
	suffix := make([]byte, suffixBytes)
	maxAttempts := 1 << entropyBits

	candidate := make([]byte, len(puzzlePrefix)+suffixBytes)
	copy(candidate, puzzlePrefix)

	for i := 0; i < maxAttempts; i++ {
		intToBytes(suffix, i)
		copy(candidate[len(puzzlePrefix):], suffix)

		kCcz := deriveKey(candidate, ad)
		block, err := aes.NewCipher(kCcz)
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		plaintext, err := gcm.Open(nil, nonce, ciphertext, ad)
		if err == nil {
			return plaintext, nil
		}
	}
	return nil, fmt.Errorf("puzzle não resolvido após %d tentativas", maxAttempts)
}

func deriveKey(k0, salt []byte) []byte {
	return argon2.IDKey(k0, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

func intToBytes(dst []byte, n int) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(n)
		n >>= 8
	}
}
