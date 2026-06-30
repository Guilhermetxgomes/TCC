package bolo_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/bolo"
)

func plateHMAC(plate string, kgov []byte) []byte {
	mac := hmac.New(sha256.New, kgov)
	mac.Write([]byte(plate))
	return mac.Sum(nil)
}

func TestBlacklistMatch(t *testing.T) {
	kgov := make([]byte, 32)
	rand.Read(kgov)

	targetPlate := "ABC1D23"
	h := plateHMAC(targetPlate, kgov)

	validUntil := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	listJSON, _ := json.Marshal(map[string]any{
		"plate_hmacs": []string{hex.EncodeToString(h)},
		"valid_until": validUntil,
	})

	bl, err := bolo.Parse(listJSON)
	if err != nil {
		t.Fatal(err)
	}

	if !bl.Match(h) {
		t.Error("placa alvo não reconhecida na lista")
	}
	if bl.Match(plateHMAC("XYZ9W99", kgov)) {
		t.Error("placa inocente reconhecida como alvo")
	}
}

func TestBlacklistExpired(t *testing.T) {
	kgov := make([]byte, 32)
	rand.Read(kgov)
	h := plateHMAC("ABC1D23", kgov)

	listJSON, _ := json.Marshal(map[string]any{
		"plate_hmacs": []string{hex.EncodeToString(h)},
		"valid_until": "2020-01-01T00:00:00Z", // já expirou
	})

	bl, err := bolo.Parse(listJSON)
	if err != nil {
		t.Fatal(err)
	}
	if bl.Match(h) {
		t.Error("lista expirada não deve gerar match")
	}
}

func TestBuildBOLORecord(t *testing.T) {
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kgov := make([]byte, 32)
	rand.Read(kgov)

	speed := float32(80.0)
	p := alpr.ALPRPlaintext{
		Plate:           "ABC1D23",
		PreciseLocation: alpr.Location{Latitude: -23.55, Longitude: -46.63},
		CapturedAt:      time.Now().UTC(),
		Speed:           &speed,
	}
	h := plateHMAC(p.Plate, kgov)

	cfg := bolo.BuildConfig{Kgov: kgov, CameraSK: sk, Region: "SP-Centro"}
	r, err := bolo.Build(p, h, cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if !bolo.VerifySignature(r, &sk.PublicKey) {
		t.Error("assinatura inválida")
	}
	if len(r.Payload.Ciphertext) == 0 {
		t.Error("payload vazio")
	}
}
