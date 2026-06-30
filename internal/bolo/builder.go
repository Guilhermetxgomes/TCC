package bolo

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
	"github.com/Guilhermetxgomes/TCC/internal/crypto/crumpling"
	"github.com/Guilhermetxgomes/TCC/internal/crypto/signing"
	"github.com/google/uuid"
)

// BuildConfig reúne as chaves para construção de um BOLORecord.
type BuildConfig struct {
	Kgov     []byte
	CameraSK *ecdsa.PrivateKey
	Region   string
}

// Build constrói um BOLORecord a partir de um ALPRPlaintext e plate_hmac já calculado.
// Usa crumpling com semente k_0' independente do banco principal (AD = placa).
func Build(p alpr.ALPRPlaintext, plateHMAC []byte, cfg BuildConfig) (alpr.BOLORecord, error) {
	plainJSON, err := json.Marshal(p)
	if err != nil {
		return alpr.BOLORecord{}, fmt.Errorf("bolo.Build marshal: %w", err)
	}

	// AD = placa (quem tem o token e sabe a placa consegue decifrar)
	ct, nonce, prefix, _, err := crumpling.Seal(plainJSON, []byte(p.Plate))
	if err != nil {
		return alpr.BOLORecord{}, fmt.Errorf("bolo.Build seal: %w", err)
	}

	capturedAt := p.CapturedAt.UTC().Truncate(time.Hour).Format(time.RFC3339)

	r := alpr.BOLORecord{
		RecordID:   uuid.New().String(),
		PlateHMAC:  plateHMAC,
		CapturedAt: capturedAt,
		Region:     cfg.Region,
		Payload: alpr.CrumpledPayload{
			Ciphertext:   ct,
			Nonce:        nonce,
			EntropyBits:  crumpling.DefaultEntropyBits,
			PuzzlePrefix: prefix,
		},
	}

	r.Signature, err = signing.Sign(cfg.CameraSK, boloMessage(r))
	if err != nil {
		return alpr.BOLORecord{}, fmt.Errorf("bolo.Build sign: %w", err)
	}
	return r, nil
}

// VerifySignature verifica a assinatura ECDSA de um BOLORecord.
func VerifySignature(r alpr.BOLORecord, cameraPK *ecdsa.PublicKey) bool {
	return signing.Verify(cameraPK, boloMessage(r), r.Signature)
}

func boloMessage(r alpr.BOLORecord) []byte {
	msg := append([]byte(r.RecordID+"|"+r.CapturedAt), r.PlateHMAC...)
	msg = append(msg, r.Payload.Ciphertext...)
	return msg
}
