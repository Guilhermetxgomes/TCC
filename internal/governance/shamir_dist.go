package governance

import (
	"crypto/ecdh"
	"fmt"

	"github.com/Guilhermetxgomes/TCC/internal/crypto/shamir"
)

// SplitSK divide a SK mensal X25519 em n shares com threshold mínimo t.
func SplitSK(sk *ecdh.PrivateKey, n, t int) ([][]byte, error) {
	shares, err := shamir.Split(sk.Bytes(), n, t)
	if err != nil {
		return nil, fmt.Errorf("governance.SplitSK: %w", err)
	}
	return shares, nil
}

// CombineSK reconstrói a SK mensal a partir de threshold ou mais shares.
// Valida que a PK derivada da SK reconstruída bate com expectedPK.
func CombineSK(shares [][]byte, expectedPK *ecdh.PublicKey) (*ecdh.PrivateKey, error) {
	skBytes, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("governance.CombineSK: %w", err)
	}

	sk, err := ecdh.X25519().NewPrivateKey(skBytes)
	if err != nil {
		return nil, fmt.Errorf("governance.CombineSK: chave inválida: %w", err)
	}

	// Verificação de integridade: PK derivada deve bater com a PK pública registrada.
	if string(sk.PublicKey().Bytes()) != string(expectedPK.Bytes()) {
		return nil, fmt.Errorf("governance.CombineSK: PK derivada não corresponde à PK registrada (shares incorretas ou insuficientes)")
	}
	return sk, nil
}
