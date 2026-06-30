package bolo

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Blacklist mantém os HMACs de placas alvo em memória.
type Blacklist struct {
	plateHMACs [][]byte
	validUntil time.Time
}

type blacklistFile struct {
	PlateHMACs []string `json:"plate_hmacs"` // hex-encoded
	ValidUntil string   `json:"valid_until"`
}

// Load carrega a lista negra de um arquivo JSON.
func Load(path string) (Blacklist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Blacklist{}, fmt.Errorf("bolo.Load: %w", err)
	}
	return Parse(data)
}

// Parse carrega a lista negra de bytes JSON — útil para testes.
func Parse(data []byte) (Blacklist, error) {
	var f blacklistFile
	if err := json.Unmarshal(data, &f); err != nil {
		return Blacklist{}, fmt.Errorf("bolo.Parse: %w", err)
	}
	validUntil, err := time.Parse(time.RFC3339, f.ValidUntil)
	if err != nil {
		return Blacklist{}, fmt.Errorf("bolo.Parse valid_until: %w", err)
	}

	hmacs := make([][]byte, 0, len(f.PlateHMACs))
	for _, h := range f.PlateHMACs {
		b, err := hex.DecodeString(h)
		if err != nil {
			return Blacklist{}, fmt.Errorf("bolo.Parse hmac hex: %w", err)
		}
		hmacs = append(hmacs, b)
	}
	return Blacklist{plateHMACs: hmacs, validUntil: validUntil}, nil
}

// Match retorna true se o plateHMAC estiver na lista e a lista ainda for válida.
func (bl Blacklist) Match(plateHMAC []byte) bool {
	if time.Now().After(bl.validUntil) {
		return false
	}
	for _, h := range bl.plateHMACs {
		if bytes.Equal(h, plateHMAC) {
			return true
		}
	}
	return false
}

// IsExpired informa se a lista negra expirou.
func (bl Blacklist) IsExpired() bool {
	return time.Now().After(bl.validUntil)
}
