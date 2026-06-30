package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// Sign assina message com a chave privada ECDSA da câmera.
// Internamente calcula SHA-256(message) e retorna assinatura no formato DER.
func Sign(sk *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, sk, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing.Sign: %w", err)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// Verify verifica uma assinatura DER produzida por Sign.
func Verify(pk *ecdsa.PublicKey, message, sig []byte) bool {
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.Verify(pk, digest[:], rs.R, rs.S)
}

// LoadOrGenerateKey carrega uma chave ECDSA P-256 de um arquivo PEM.
// Se o arquivo não existir, gera uma nova chave e a salva.
func LoadOrGenerateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return generateAndSave(path)
	}
	if err != nil {
		return nil, fmt.Errorf("signing.LoadOrGenerateKey: %w", err)
	}
	return parseKey(data)
}

func generateAndSave(path string) (*ecdsa.PrivateKey, error) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signing.generateAndSave: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(sk)
	if err != nil {
		return nil, fmt.Errorf("signing.generateAndSave marshal: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, fmt.Errorf("signing.generateAndSave write: %w", err)
	}
	return sk, nil
}

func parseKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signing.parseKey: PEM inválido")
	}
	sk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing.parseKey: %w", err)
	}
	return sk, nil
}
