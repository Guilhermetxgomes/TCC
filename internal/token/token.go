package token

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Guilhermetxgomes/TCC/internal/crypto/signing"
)

// SearchType define o tipo de busca autorizado pelo token.
type SearchType string

const (
	SearchOpen   SearchType = "open"
	SearchClosed SearchType = "closed"
	SearchBOLO   SearchType = "bolo"
)

// AuthToken é o token de autorização emitido pela governança/juiz.
// A assinatura cobre todos os campos exceto Signature.
type AuthToken struct {
	TokenID    string     `json:"token_id"`
	SearchType SearchType `json:"search_type"`
	// Campos específicos por tipo:
	CameraID  string `json:"camera_id,omitempty"`  // open
	PlateHMAC string `json:"plate_hmac,omitempty"` // closed, bolo
	Start     string `json:"start,omitempty"`      // open (RFC3339)
	End       string `json:"end,omitempty"`        // open (RFC3339)

	DecodedBy string `json:"decoded_by"` // nome do investigador
	ExpiresAt string `json:"expires_at"` // RFC3339

	Signature []byte `json:"signature"`
}

// Parse desserializa um token JSON.
func Parse(raw []byte) (AuthToken, error) {
	var t AuthToken
	if err := json.Unmarshal(raw, &t); err != nil {
		return AuthToken{}, fmt.Errorf("token.Parse: %w", err)
	}
	return t, nil
}

// Verify verifica a assinatura ECDSA e a validade temporal do token.
func Verify(t AuthToken, judgePK *ecdsa.PublicKey) error {
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return fmt.Errorf("token: expires_at inválido: %w", err)
	}
	if time.Now().After(exp) {
		return fmt.Errorf("token expirado em %s", t.ExpiresAt)
	}

	msg, err := tokenMessage(t)
	if err != nil {
		return err
	}
	if !signing.Verify(judgePK, msg, t.Signature) {
		return fmt.Errorf("token: assinatura inválida")
	}
	return nil
}

// Issue cria e assina um novo token (usado pela governança/juiz).
func Issue(t *AuthToken, judgeSK *ecdsa.PrivateKey) error {
	msg, err := tokenMessage(*t)
	if err != nil {
		return err
	}
	sig, err := signing.Sign(judgeSK, msg)
	if err != nil {
		return fmt.Errorf("token.Issue: %w", err)
	}
	t.Signature = sig
	return nil
}

// tokenMessage serializa os campos do token (sem Signature) para assinar/verificar.
func tokenMessage(t AuthToken) ([]byte, error) {
	copy := t
	copy.Signature = nil
	b, err := json.Marshal(copy)
	if err != nil {
		return nil, fmt.Errorf("token: marshal para assinatura: %w", err)
	}
	return b, nil
}
