package governance

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"time"
)

// GenerateMonthlyKeyPair gera um par X25519 para a busca total do mês corrente.
func GenerateMonthlyKeyPair() (*ecdh.PrivateKey, error) {
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("governance.GenerateMonthlyKeyPair: %w", err)
	}
	return sk, nil
}

// GenerateKgov gera 32 bytes aleatórios usados como chave HMAC de placa.
func GenerateKgov() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("governance.GenerateKgov: %w", err)
	}
	return k, nil
}

// KeyMonth retorna o identificador do mês corrente no formato "YYYY-MM".
func KeyMonth() string {
	return time.Now().UTC().Format("2006-01")
}
