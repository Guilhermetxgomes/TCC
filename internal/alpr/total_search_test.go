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

func TestDecryptTotal_RoundTrip(t *testing.T) {
	cameraSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	monthlySK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kgov := make([]byte, 32)
	rand.Read(kgov)

	cfg := alpr.BuildConfig{
		CameraID:  "CAM-TOTAL-001",
		KeyMonth:  "2026-06",
		Kgov:      kgov,
		MonthlyPK: monthlySK.PublicKey(),
		CameraSK:  cameraSK,
	}

	speed := float32(90.0)
	original := alpr.ALPRPlaintext{
		Plate:           "TCC5T54",
		PreciseLocation: alpr.Location{Latitude: -23.561, Longitude: -46.655},
		CapturedAt:      time.Now().UTC().Truncate(time.Second),
		Confidence:      0.98,
		Speed:           &speed,
	}

	rec, err := alpr.Build(original, cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	recovered, err := alpr.DecryptTotal(rec, monthlySK)
	if err != nil {
		t.Fatalf("DecryptTotal: %v", err)
	}

	if recovered.Plate != original.Plate {
		t.Errorf("Plate: esperado %q, got %q", original.Plate, recovered.Plate)
	}
	if recovered.PreciseLocation != original.PreciseLocation {
		t.Errorf("Location: esperado %v, got %v", original.PreciseLocation, recovered.PreciseLocation)
	}
	if !recovered.CapturedAt.Equal(original.CapturedAt) {
		t.Errorf("CapturedAt: esperado %v, got %v", original.CapturedAt, recovered.CapturedAt)
	}
}

func TestDecryptTotal_WrongKey(t *testing.T) {
	cameraSK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	monthlySK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongSK, _ := ecdh.X25519().GenerateKey(rand.Reader)
	kgov := make([]byte, 32)
	rand.Read(kgov)

	cfg := alpr.BuildConfig{
		CameraID:  "CAM-TOTAL-002",
		KeyMonth:  "2026-06",
		Kgov:      kgov,
		MonthlyPK: monthlySK.PublicKey(),
		CameraSK:  cameraSK,
	}

	rec, err := alpr.Build(alpr.ALPRPlaintext{
		Plate:      "WRONGK1",
		CapturedAt: time.Now().UTC(),
	}, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := alpr.DecryptTotal(rec, wrongSK); err == nil {
		t.Error("chave errada deveria retornar erro na decifração")
	}
}
