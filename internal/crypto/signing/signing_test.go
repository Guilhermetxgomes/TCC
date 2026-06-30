package signing_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
