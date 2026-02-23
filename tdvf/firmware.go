package tdvf

import (
	"fmt"
	"os"

	"gitlab.com/real-cis/cc/go-trust/tdvf/mrtd"
)

type Measurements interface {
	GetMRTD() []byte
	GetCFV() []byte
	GetSecureBoot() SecureBootVars
}

// TDVFMeasurements contains all measurements extracted from a TDVF firmware image.
type TDVFMeasurements struct {
	MRTD       []byte
	CFV        []byte
	SecureBoot SecureBootVars
}

func (m *TDVFMeasurements) GetMRTD() []byte {
	return m.MRTD
}

func (m *TDVFMeasurements) GetCFV() []byte {
	return m.CFV
}

func (m *TDVFMeasurements) GetSecureBoot() SecureBootVars {
	return m.SecureBoot
}

// MeasureFirmware parses a TDVF firmware file and extracts all measurements.
//
// filePath is the path to the firmware file
// qemuCompat indicates whether to use QEMU compatible measurement for MRTD.
func MeasureFirmware(filePath string, qemuCompat bool) (Measurements, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	mrtdHash, err := mrtd.BuildMRTD(data, qemuCompat)
	if err != nil {
		return nil, fmt.Errorf("failed to build MRTD: %w", err)
	}

	cfvMeasurements, err := MeasureCFV(data)
	if err != nil {
		return nil, fmt.Errorf("failed to measure CFV: %w", err)
	}

	return &TDVFMeasurements{
		MRTD:       mrtdHash,
		CFV:        cfvMeasurements.CFV,
		SecureBoot: cfvMeasurements.SecureBoot,
	}, nil
}
