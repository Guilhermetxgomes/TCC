package alpr_test

import (
	"regexp"
	"testing"

	"github.com/Guilhermetxgomes/TCC/internal/alpr"
)

var mercosulPattern = regexp.MustCompile(`^[A-Z]{3}[0-9][A-Z][0-9]{2}$`)

func TestNewCaptureGeneratesValidPlate(t *testing.T) {
	for range 100 {
		c := alpr.NewCapture("CAM-TEST-001")
		if !mercosulPattern.MatchString(c.Plate) {
			t.Errorf("placa inválida: %s", c.Plate)
		}
	}
}

func TestNewCaptureFields(t *testing.T) {
	c := alpr.NewCapture("CAM-SP-0042")

	if c.CameraID != "CAM-SP-0042" {
		t.Errorf("camera_id esperado CAM-SP-0042, got %s", c.CameraID)
	}
	if c.CapturedAt.IsZero() {
		t.Error("captured_at não deve ser zero")
	}
	if c.Confidence < 0.85 || c.Confidence > 1.0 {
		t.Errorf("confidence fora do intervalo: %f", c.Confidence)
	}
	if c.Speed == nil || *c.Speed < 0 || *c.Speed > 120 {
		t.Error("speed inválido")
	}
	if c.Location.Latitude < -23.70 || c.Location.Latitude > -23.45 {
		t.Errorf("latitude fora de SP: %f", c.Location.Latitude)
	}
}

func TestToPlaintext(t *testing.T) {
	c := alpr.NewCapture("CAM-001")
	p := c.ToPlaintext()

	if p.Plate != c.Plate {
		t.Errorf("placa divergente: %s != %s", p.Plate, c.Plate)
	}
	if p.CapturedAt != c.CapturedAt {
		t.Error("captured_at divergente")
	}
}
