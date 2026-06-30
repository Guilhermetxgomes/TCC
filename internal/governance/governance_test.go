package governance_test

import (
	"path/filepath"
	"testing"

	"github.com/Guilhermetxgomes/TCC/internal/governance"
)

func TestGenerateMonthlyKeyPair(t *testing.T) {
	sk, err := governance.GenerateMonthlyKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if sk == nil {
		t.Fatal("sk nil")
	}
	if len(sk.Bytes()) != 32 {
		t.Errorf("SK X25519 esperada com 32 bytes, got %d", len(sk.Bytes()))
	}
	// PK derivada deve ser exportável
	pk := sk.PublicKey()
	if len(pk.Bytes()) != 32 {
		t.Errorf("PK X25519 esperada com 32 bytes, got %d", len(pk.Bytes()))
	}
}

func TestGenerateKgov(t *testing.T) {
	k, err := governance.GenerateKgov()
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 32 {
		t.Errorf("K_gov esperada com 32 bytes, got %d", len(k))
	}
	// Duas gerações devem ser diferentes
	k2, _ := governance.GenerateKgov()
	same := true
	for i := range k {
		if k[i] != k2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("duas gerações de K_gov idênticas (entropia insuficiente?)")
	}
}

func TestKeyMonth(t *testing.T) {
	m := governance.KeyMonth()
	if len(m) != 7 { // "YYYY-MM"
		t.Errorf("KeyMonth formato inesperado: %q", m)
	}
}

func TestSaveLoadMonthlyKey(t *testing.T) {
	sk, err := governance.GenerateMonthlyKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	passphrase := []byte("senha-de-teste-nao-use-em-producao")
	path := filepath.Join(t.TempDir(), "monthly.key")

	if err := governance.SaveMonthlyKey(path, sk, passphrase); err != nil {
		t.Fatalf("SaveMonthlyKey: %v", err)
	}

	loaded, keyMonth, err := governance.LoadMonthlyKey(path, passphrase)
	if err != nil {
		t.Fatalf("LoadMonthlyKey: %v", err)
	}

	if string(sk.Bytes()) != string(loaded.Bytes()) {
		t.Error("SK carregada difere da original")
	}
	if keyMonth == "" {
		t.Error("key_month vazio")
	}
}

func TestLoadMonthlyKey_WrongPassphrase(t *testing.T) {
	sk, _ := governance.GenerateMonthlyKeyPair()
	path := filepath.Join(t.TempDir(), "monthly.key")
	governance.SaveMonthlyKey(path, sk, []byte("correta"))

	_, _, err := governance.LoadMonthlyKey(path, []byte("errada"))
	if err == nil {
		t.Error("passphrase errada deveria retornar erro")
	}
}
