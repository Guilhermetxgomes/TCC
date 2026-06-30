package shamir_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/Guilhermetxgomes/TCC/internal/crypto/shamir"
)

func randomSecret(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip_ExactThreshold(t *testing.T) {
	secret := randomSecret(t, 32)
	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("esperado 5 shares, got %d", len(shares))
	}

	recovered, err := shamir.Combine(shares[:3])
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Error("segredo recuperado difere do original (3 de 5 shares)")
	}
}

func TestRoundTrip_AllShares(t *testing.T) {
	secret := randomSecret(t, 32)
	shares, _ := shamir.Split(secret, 5, 3)

	recovered, err := shamir.Combine(shares)
	if err != nil {
		t.Fatalf("Combine com todas as shares: %v", err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Error("segredo recuperado difere com todas as shares")
	}
}

func TestRoundTrip_ArbitrarySubset(t *testing.T) {
	secret := randomSecret(t, 32)
	shares, _ := shamir.Split(secret, 5, 3)

	// Usa shares 0, 2, 4 (não consecutivas)
	subset := [][]byte{shares[0], shares[2], shares[4]}
	recovered, err := shamir.Combine(subset)
	if err != nil {
		t.Fatalf("Combine subconjunto: %v", err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Error("subconjunto não-consecutivo falhou")
	}
}

func TestBelowThreshold_DoesNotRecoverSecret(t *testing.T) {
	secret := randomSecret(t, 32)
	shares, _ := shamir.Split(secret, 5, 3)

	// t-1 = 2 shares — não deve reconstruir o segredo
	recovered, err := shamir.Combine(shares[:2])
	if err != nil {
		// erro aceitável
		return
	}
	if bytes.Equal(secret, recovered) {
		t.Error("2 shares (abaixo do threshold) não deveriam reconstruir o segredo")
	}
}

func TestSplit_MinimalParams(t *testing.T) {
	secret := randomSecret(t, 32)
	shares, err := shamir.Split(secret, 2, 2)
	if err != nil {
		t.Fatalf("Split(2,2): %v", err)
	}
	recovered, err := shamir.Combine(shares)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, recovered) {
		t.Error("falhou com n=2, t=2")
	}
}

func TestSplit_InvalidParams(t *testing.T) {
	secret := randomSecret(t, 32)

	if _, err := shamir.Split(secret, 3, 1); err == nil {
		t.Error("threshold=1 deveria retornar erro")
	}
	if _, err := shamir.Split(secret, 2, 3); err == nil {
		t.Error("n < threshold deveria retornar erro")
	}
	if _, err := shamir.Split(nil, 3, 2); err == nil {
		t.Error("segredo vazio deveria retornar erro")
	}
}

func TestCombine_DuplicateShares(t *testing.T) {
	secret := randomSecret(t, 32)
	shares, _ := shamir.Split(secret, 5, 3)

	dup := [][]byte{shares[0], shares[0], shares[1]} // share[0] duplicada
	if _, err := shamir.Combine(dup); err == nil {
		t.Error("shares com índice duplicado deveriam retornar erro")
	}
}

func TestGF256_MultiplicationProperty(t *testing.T) {
	// Verificação indireta: Split + Combine de segredo constante 0xFF
	secret := bytes.Repeat([]byte{0xFF}, 32)
	shares, _ := shamir.Split(secret, 5, 3)
	recovered, _ := shamir.Combine(shares[:3])
	if !bytes.Equal(secret, recovered) {
		t.Error("falhou com segredo 0xFF (teste de multiplicação GF(256))")
	}
}
