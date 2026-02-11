package tdvf

import (
	"encoding/hex"
	"testing"
)

const (
	expectedPKHex  = "1e71413273207ab39c817a24f5f97f1e8ee63b1086c602c675a348da63b06855f75a3916e92647c84c0c92b2513c400c"
	expectedCFVHex = "cc7dbc6e48cd02d110c75a560eb35b6fba8e1665576fe2103dc1c78a9acc73fe386c2b1778c980e91e51f0af9e25569b"
)

func TestParseFirmware(t *testing.T) {
	filePath := "mrtd/testdata/OVMF.fd"
	measurements, err := MeasureFirmware(filePath, true)
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

	// Verify CFV measurement is present
	cfv := measurements.GetCFV()
	if cfv == nil {
		t.Fatal("Expected CFV measurements, got nil")
	}
	cfvHex := hex.EncodeToString(cfv)
	if cfvHex != expectedCFVHex {
		t.Fatalf("CFV mismatch: expected %s, got %s", expectedCFVHex, cfvHex)
	}

	// compare PK to expected value
	pkHex := hex.EncodeToString(measurements.GetSecureBoot().PK)
	if pkHex != expectedPKHex {
		t.Fatalf("PK mismatch: expected %s, got %s", expectedPKHex, pkHex)
	}

}
