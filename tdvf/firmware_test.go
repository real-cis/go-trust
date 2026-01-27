package tdvf

import (
	"encoding/hex"
	"testing"
)

const (
	expectedPKHex = "1e71413273207ab39c817a24f5f97f1e8ee63b1086c602c675a348da63b06855f75a3916e92647c84c0c92b2513c400c"
)

func TestParseFirmware(t *testing.T) {
	filePath := "mrtd/testdata/OVMF.fd"
	measurements, err := MeasureFirmware(filePath)
	if err != nil {
		t.Fatalf("ParseFirmware failed: %v", err)
	}
	if measurements == nil {
		t.Fatal("Expected measurements, got nil")
	}

	// Verify MRTD if possible
	if len(measurements.GetMRTD()) == 0 {
		t.Error("Expected MRTD to be present")
	}

	// compare PK to expected value
	pkHex := hex.EncodeToString(measurements.GetSecureBoot().PK)
	if pkHex != expectedPKHex {
		t.Fatalf("PK mismatch: expected %s, got %s", expectedPKHex, pkHex)
	}
}

func TestMeasureFirmwareInterface(t *testing.T) {
	filePath := "mrtd/testdata/OVMF.fd"

	var measurements Measurements
	var err error
	measurements, err = MeasureFirmware(filePath)
	if err != nil {
		t.Fatalf("MeasureFirmware failed: %v", err)
	}
	if measurements == nil {
		t.Fatal("Expected measurements, got nil")
	}

	mrtd := measurements.GetMRTD()
	if len(mrtd) == 0 {
		t.Error("Expected MRTD to be present")
	}

	sb := measurements.GetSecureBoot()
	pkHex := hex.EncodeToString(sb.PK)
	if pkHex != expectedPKHex {
		t.Fatalf("PK mismatch: expected %s, got %s", expectedPKHex, pkHex)
	}
}
