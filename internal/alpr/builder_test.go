package alpr_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
)

func testConfig(t *testing.T) alpr.BuildConfig {
	t.Helper()
	cameraSK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	monthlySK, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kgov := make([]byte, 32)
	rand.Read(kgov)

	return alpr.BuildConfig{
		CameraID:  "CAM-TEST-001",
		KeyMonth:  "2026-06",
		Kgov:      kgov,
		MonthlyPK: monthlySK.PublicKey(),
		CameraSK:  cameraSK,
	}
}

func testPlaintext() alpr.ALPRPlaintext {
	speed := float32(60.0)
	return alpr.ALPRPlaintext{
		Plate:           "ABC1D23",
		PreciseLocation: alpr.Location{Latitude: -23.55, Longitude: -46.63},
		CapturedAt:      time.Now().UTC(),
		Confidence:      0.97,
		Speed:           &speed,
	}
}

func TestBuildProducesValidRecord(t *testing.T) {
	cfg := testConfig(t)
	p := testPlaintext()

	r, err := alpr.Build(p, cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if r.RecordID == "" {
		t.Error("record_id vazio")
	}
	if len(r.PlateHMAC) == 0 {
		t.Error("plate_hmac vazio")
	}
	if len(r.OpenPayload.Ciphertext) == 0 {
		t.Error("open_payload vazio")
	}
	if len(r.ClosedPayload.Ciphertext) == 0 {
		t.Error("closed_payload vazio")
	}
	if len(r.TotalPayload.Ciphertext) == 0 {
		t.Error("total_payload vazio")
	}
	if len(r.Signature) == 0 {
		t.Error("signature vazia")
	}
}

func TestBuildSignatureVerifies(t *testing.T) {
	cfg := testConfig(t)
	r, err := alpr.Build(testPlaintext(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !alpr.VerifySignature(r, &cfg.CameraSK.PublicKey) {
		t.Error("assinatura inválida para chave correta")
	}
}

func TestBuildSignatureRejectsWrongKey(t *testing.T) {
	cfg := testConfig(t)
	r, err := alpr.Build(testPlaintext(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	otherSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if alpr.VerifySignature(r, &otherSK.PublicKey) {
		t.Error("assinatura aceita chave errada")
	}
}

func TestBuildDifferentRecordsHaveDifferentIDs(t *testing.T) {
	cfg := testConfig(t)
	r1, _ := alpr.Build(testPlaintext(), cfg)
	r2, _ := alpr.Build(testPlaintext(), cfg)
	if r1.RecordID == r2.RecordID {
		t.Error("dois registros com o mesmo record_id")
	}
}
