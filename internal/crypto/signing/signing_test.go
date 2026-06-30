package signing_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/Guilhermetxgomes/TCC/internal/crypto/signing"
)

func TestSignVerify(t *testing.T) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("record_id:abc|camera:CAM-001|captured_at:2026-06-29T14:00:00Z")

	sig, err := signing.Sign(sk, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !signing.Verify(&sk.PublicKey, message, sig) {
		t.Fatal("Verify retornou false para assinatura válida")
	}
}

func TestVerifyRejectsWrongMessage(t *testing.T) {
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, _ := signing.Sign(sk, []byte("mensagem original"))

	if signing.Verify(&sk.PublicKey, []byte("mensagem alterada"), sig) {
		t.Fatal("Verify aceitou mensagem alterada")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	sk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sk2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	message := []byte("mensagem")
	sig, _ := signing.Sign(sk1, message)

	if signing.Verify(&sk2.PublicKey, message, sig) {
		t.Fatal("Verify aceitou chave errada")
	}
}

func TestVerifyRejectsCorruptedSignature(t *testing.T) {
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	message := []byte("mensagem")
	sig, _ := signing.Sign(sk, message)

	sig[0] ^= 0xFF // corrompe o primeiro byte

	if signing.Verify(&sk.PublicKey, message, sig) {
		t.Fatal("Verify aceitou assinatura corrompida")
	}
}

func TestLoadOrGenerateKey_GeneratesWhenAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cam.pem")

	sk, err := signing.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	if sk == nil {
		t.Fatal("chave nula")
	}

	// Arquivo deve ter sido criado
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("arquivo não criado: %v", err)
	}

	// Round-trip: carrega do arquivo
	sk2, err := signing.LoadOrGenerateKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey (reload): %v", err)
	}

	// Chave recarregada deve produzir assinaturas verificáveis pela PK original
	msg := []byte("round-trip")
	sig, _ := signing.Sign(sk2, msg)
	if !signing.Verify(&sk.PublicKey, msg, sig) {
		t.Error("chave recarregada não é a mesma que a gerada")
	}
}

func TestLoadOrGenerateKey_RejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	os.WriteFile(path, []byte("not a pem"), 0600)

	if _, err := signing.LoadOrGenerateKey(path); err == nil {
		t.Fatal("esperava erro com PEM inválido")
	}
}
