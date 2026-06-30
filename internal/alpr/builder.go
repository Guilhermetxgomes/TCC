package alpr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/crypto/crumpling"
	"github.com/Guilhermetxgomes/TCC/internal/crypto/ecc"
	"github.com/Guilhermetxgomes/TCC/internal/crypto/signing"

	"github.com/google/uuid"
)

// BuildConfig reúne as chaves necessárias para construir um ALPRRecord.
type BuildConfig struct {
	CameraID  string
	KeyMonth  string            // ex: "2026-06"
	Kgov      []byte            // chave HMAC de governança
	MonthlyPK *ecdh.PublicKey   // PK mensal para cifração de emergência
	CameraSK  *ecdsa.PrivateKey // chave de assinatura da câmera
}

// Build constrói um ALPRRecord completo a partir de um ALPRPlaintext.
func Build(p ALPRPlaintext, cfg BuildConfig) (ALPRRecord, error) {
	plainJSON, err := json.Marshal(p)
	if err != nil {
		return ALPRRecord{}, fmt.Errorf("alpr.Build marshal: %w", err)
	}

	recordID := uuid.New().String()
	capturedAt := p.CapturedAt.UTC().Truncate(time.Hour).Format(time.RFC3339)
	plateHMAC := computeHMAC([]byte(p.Plate), cfg.Kgov)

	// Busca Aberta: AD = camera_id|captured_at
	adOpen := []byte(cfg.CameraID + "|" + capturedAt)
	openCT, openNonce, openPrefix, _, err := crumpling.Seal(plainJSON, adOpen)
	if err != nil {
		return ALPRRecord{}, fmt.Errorf("alpr.Build open: %w", err)
	}

	// Busca Fechada: AD = placa
	adClosed := []byte(p.Plate)
	closedCT, closedNonce, closedPrefix, _, err := crumpling.Seal(plainJSON, adClosed)
	if err != nil {
		return ALPRRecord{}, fmt.Errorf("alpr.Build closed: %w", err)
	}

	// Busca Total: cifra plaintext com k efêmero, lacra k com PK mensal
	totalCT, totalNonce, encKey, ephPK, err := sealTotal(plainJSON, cfg.MonthlyPK)
	if err != nil {
		return ALPRRecord{}, fmt.Errorf("alpr.Build total: %w", err)
	}

	r := ALPRRecord{
		RecordID:   recordID,
		CameraID:   cfg.CameraID,
		CapturedAt: capturedAt,
		KeyMonth:   cfg.KeyMonth,
		PlateHMAC:  plateHMAC,
		OpenPayload: CrumpledPayload{
			Ciphertext:   openCT,
			Nonce:        openNonce,
			EntropyBits:  crumpling.DefaultEntropyBits,
			PuzzlePrefix: openPrefix,
		},
		ClosedPayload: CrumpledPayload{
			Ciphertext:   closedCT,
			Nonce:        closedNonce,
			EntropyBits:  crumpling.DefaultEntropyBits,
			PuzzlePrefix: closedPrefix,
		},
		TotalPayload: ECCPayload{
			Ciphertext:   totalCT,
			Nonce:        totalNonce,
			EncryptedKey: encKey,
			EphemeralPK:  ephPK,
		},
	}

	r.Signature, err = signing.Sign(cfg.CameraSK, recordMessage(r))
	if err != nil {
		return ALPRRecord{}, fmt.Errorf("alpr.Build sign: %w", err)
	}
	return r, nil
}

// VerifySignature verifica a assinatura ECDSA de um ALPRRecord.
func VerifySignature(r ALPRRecord, cameraPK *ecdsa.PublicKey) bool {
	return signing.Verify(cameraPK, recordMessage(r), r.Signature)
}

// recordMessage compõe a mensagem que é assinada/verificada.
func recordMessage(r ALPRRecord) []byte {
	h := sha256.New()
	h.Write([]byte(strings.Join([]string{
		r.RecordID, r.CameraID, r.CapturedAt,
	}, "|")))
	h.Write(r.PlateHMAC)
	h.Write(sha256sum(r.OpenPayload.Ciphertext))
	h.Write(sha256sum(r.ClosedPayload.Ciphertext))
	h.Write(sha256sum(r.TotalPayload.Ciphertext))
	return h.Sum(nil)
}

func computeHMAC(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// sealTotal cifra plaintext com chave efêmera k e lacra k com a PK mensal.
func sealTotal(plaintext []byte, monthlyPK *ecdh.PublicKey) (ct, nonce, encKey, ephPK []byte, err error) {
	k := make([]byte, 32)
	if _, err = rand.Read(k); err != nil {
		return
	}

	nonce = make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	ct = gcm.Seal(nil, nonce, plaintext, nil)

	encKey, ephPK, err = ecc.SealKey(k, monthlyPK)
	return
}
