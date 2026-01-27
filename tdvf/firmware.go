package tdvf

import (
	"fmt"
	"os"

	"gitlab.com/real-cis/cc/go-trust/tdvf/mrtd"
)

type Measurements interface {
	GetMRTD() []byte
	GetSecureBoot() SecureBootVars
}

// TDVFMeasurements contains all measurements extracted from a TDVF firmware image.
type TDVFMeasurements struct {
	MRTD       []byte
	SecureBoot SecureBootVars
}

func (m *TDVFMeasurements) GetMRTD() []byte {
	return m.MRTD
}

func (m *TDVFMeasurements) GetSecureBoot() SecureBootVars {
	return m.SecureBoot
}

// MeasureFirmware parses a TDVF firmware file and extracts all measurements.
func MeasureFirmware(filename string) (Measurements, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	mrtdHash, err := mrtd.BuildMRTD(data, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build MRTD: %w", err)
	}

	sbVars, err := MeasureSecureBootVariables(data)
	if err != nil {
		return nil, fmt.Errorf("failed to measure secure boot variables: %w", err)
	}

	return &TDVFMeasurements{
		MRTD:       mrtdHash,
		SecureBoot: *sbVars,
	}, nil
}
