package alpr

import (
	"fmt"
	"math/rand"
	"time"
)

// Capture representa uma captura bruta do sistema ALPR antes da cifragem.
type Capture struct {
	Plate      string
	CameraID   string
	Location   Location
	CapturedAt time.Time
	Confidence float32
	Speed      *float32
}

var (
	mercosulLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits          = "0123456789"

	// Coordenadas aproximadas de São Paulo (bounding box)
	spLatMin, spLatMax = -23.70, -23.45
	spLonMin, spLonMax = -46.80, -46.55
)

// NewCapture gera uma captura ALPR simulada com dados realistas de São Paulo.
func NewCapture(cameraID string) Capture {
	speed := float32(rand.Intn(121)) // 0–120 km/h
	return Capture{
		Plate:    randomMercosulPlate(),
		CameraID: cameraID,
		Location: Location{
			Latitude:  spLatMin + rand.Float64()*(spLatMax-spLatMin),
			Longitude: spLonMin + rand.Float64()*(spLonMax-spLonMin),
		},
		CapturedAt: time.Now().UTC(),
		Confidence: 0.85 + rand.Float32()*0.15, // 0.85–1.00
		Speed:      &speed,
	}
}

// ToPlaintext converte uma Capture em ALPRPlaintext para cifragem.
func (c Capture) ToPlaintext() ALPRPlaintext {
	return ALPRPlaintext{
		Plate:           c.Plate,
		PreciseLocation: c.Location,
		CapturedAt:      c.CapturedAt,
		Confidence:      c.Confidence,
		Speed:           c.Speed,
	}
}

// randomMercosulPlate gera uma placa no formato Mercosul: ABC1D23
func randomMercosulPlate() string {
	return fmt.Sprintf("%c%c%c%c%c%c%c",
		mercosulLetters[rand.Intn(len(mercosulLetters))],
		mercosulLetters[rand.Intn(len(mercosulLetters))],
		mercosulLetters[rand.Intn(len(mercosulLetters))],
		digits[rand.Intn(len(digits))],
		mercosulLetters[rand.Intn(len(mercosulLetters))],
		digits[rand.Intn(len(digits))],
		digits[rand.Intn(len(digits))],
	)
}
