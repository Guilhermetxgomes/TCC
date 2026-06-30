package alpr

import "time"

// ALPRRecord é a unidade atômica de dado do sistema.
// Contrato entre coletor (Marco 2) e servidor de custódia (Marco 3).
// Schema completo: docs/schema/alpr-record.md
type ALPRRecord struct {
	RecordID      string          `json:"record_id"`
	CameraID      string          `json:"camera_id"`
	CapturedAt    string          `json:"captured_at"`
	Region        string          `json:"region"`
	KeyMonth      string          `json:"key_month"`
	PlateHMAC     []byte          `json:"plate_hmac"`
	OpenPayload   CrumpledPayload `json:"open_payload"`
	ClosedPayload CrumpledPayload `json:"closed_payload"`
	TotalPayload  ECCPayload      `json:"total_payload"`
	Signature     []byte          `json:"signature"`
}

// BOLORecord é o registro exclusivo do banco BOLO.
type BOLORecord struct {
	RecordID   string          `json:"record_id"`
	PlateHMAC  []byte          `json:"plate_hmac"`
	CapturedAt string          `json:"captured_at"`
	Region     string          `json:"region"`
	Payload    CrumpledPayload `json:"payload"`
	Signature  []byte          `json:"signature"`
}

type CrumpledPayload struct {
	Ciphertext   []byte `json:"ciphertext"`
	Nonce        []byte `json:"nonce"`
	EntropyBits  uint8  `json:"entropy_bits"`
	PuzzlePrefix []byte `json:"puzzle_prefix"`
}

type ECCPayload struct {
	Ciphertext   []byte `json:"ciphertext"`
	Nonce        []byte `json:"nonce"`
	EncryptedKey []byte `json:"encrypted_key"`
	EphemeralPK  []byte `json:"ephemeral_pk"`
}

type ALPRPlaintext struct {
	Plate           string    `json:"plate"`
	PreciseLocation Location  `json:"precise_location"`
	CapturedAt      time.Time `json:"captured_at"`
	ImageHash       []byte    `json:"image_hash"`
	Confidence      float32   `json:"confidence"`
	Speed           *float32  `json:"speed,omitempty"`
}

type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}
