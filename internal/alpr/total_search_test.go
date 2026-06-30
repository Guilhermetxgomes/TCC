package alpr_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/governance"
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

// TestEmergencyAccessE2E testa o ciclo completo de acesso excepcional (T5.5):
// geração de SK → split → cifração de registro → reconstrução via 3 shares → decifração.
func TestEmergencyAccessE2E(t *testing.T) {
	// 1. Governança gera SK mensal X25519 e divide em 5 shares (threshold=3)
	monthlySK, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	monthlyPK := monthlySK.PublicKey()

	shares, err := governance.SplitSK(monthlySK, 5, 3)
	if err != nil {
		t.Fatalf("SplitSK: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("esperado 5 shares, got %d", len(shares))
	}

	// 2. Câmera captura placa e constrói ALPRRecord (total payload cifrado com PK mensal)
	cameraSK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey ECDSA: %v", err)
	}
	kgov := make([]byte, 32)
	rand.Read(kgov)

	cfg := alpr.BuildConfig{
		CameraID:  "CAM-E2E-001",
		KeyMonth:  "2026-06",
		Kgov:      kgov,
		MonthlyPK: monthlyPK,
		CameraSK:  cameraSK,
	}

	speed := float32(72.5)
	original := alpr.ALPRPlaintext{
		Plate:           "E2ET5S5",
		PreciseLocation: alpr.Location{Latitude: -23.5505, Longitude: -46.6333},
		CapturedAt:      time.Now().UTC().Truncate(time.Second),
		Confidence:      0.97,
		Speed:           &speed,
	}

	rec, err := alpr.Build(original, cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// 3. Comitê submete 3 shares (índices 0, 2, 4) → reconstrói SK mensal
	selected := [][]byte{shares[0], shares[2], shares[4]}
	reconstructedSK, err := governance.CombineSK(selected, monthlyPK)
	if err != nil {
		t.Fatalf("CombineSK com 3 shares: %v", err)
	}

	// 4. Investigador usa SK reconstruída + DecryptTotal para decifrar o registro
	recovered, err := alpr.DecryptTotal(rec, reconstructedSK)
	if err != nil {
		t.Fatalf("DecryptTotal: %v", err)
	}

	// 5. Plaintext recuperado bate com o original
	if recovered.Plate != original.Plate {
		t.Errorf("Plate: esperado %q, got %q", original.Plate, recovered.Plate)
	}
	if recovered.PreciseLocation != original.PreciseLocation {
		t.Errorf("Location: esperado %v, got %v", original.PreciseLocation, recovered.PreciseLocation)
	}
	if !recovered.CapturedAt.Equal(original.CapturedAt) {
		t.Errorf("CapturedAt: esperado %v, got %v", original.CapturedAt, recovered.CapturedAt)
	}

	// 6. Verifica que t-1=2 shares não reconstroem a SK corretamente
	twoShares := [][]byte{shares[0], shares[1]}
	badSK, err := governance.CombineSK(twoShares, monthlyPK)
	if err == nil {
		// CombineSK pode retornar a SK errada ou um erro; se não errar, DecryptTotal deve falhar
		_, decErr := alpr.DecryptTotal(rec, badSK)
		if decErr == nil {
			t.Error("2 shares (abaixo do threshold) não deveriam decifrar o registro com sucesso")
		}
	}
	// err != nil é o caso esperado: CombineSK detectou PK incorreta
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
