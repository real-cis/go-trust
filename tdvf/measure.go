package tdvf

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"gitlab.com/real-cis/cc/go-trust/tdvf/edk2"
)

// measureSHA384 computes a SHA384 hash of the given data
func measureSHA384(data []byte) []byte {
	hash := sha512.New384()
	hash.Write(data)
	return hash.Sum(nil)
}

func encodeGUID(guidStr string) ([]byte, error) {
	data := make([]byte, 0, 16)
	atoms := strings.Split(guidStr, "-")

	if len(atoms) != 5 {
		return nil, fmt.Errorf("invalid GUID format")
	}

	for idx, atom := range atoms {
		raw, err := hex.DecodeString(atom)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex in GUID: %w", err)
		}

		if idx <= 2 {
			// Little-endian: reverse the bytes
			for i := len(raw) - 1; i >= 0; i-- {
				data = append(data, raw[i])
			}
		} else {
			// Big-endian: keep as-is
			data = append(data, raw...)
		}
	}

	return data, nil
}

func MeasureTdxEfiVariable(vendorGUID, varName string, varData []byte) ([]byte, error) {
	var data []byte

	guidBytes, err := encodeGUID(vendorGUID)
	if err != nil {
		return nil, err
	}
	data = append(data, guidBytes...)

	// Variable name length
	nameLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nameLenBytes, uint64(len(varName)))
	data = append(data, nameLenBytes...)

	// Variable data size
	dataSize := uint64(0)
	if varData != nil {
		dataSize = uint64(len(varData))
	}
	dataSizeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(dataSizeBytes, dataSize)
	data = append(data, dataSizeBytes...)

	// Add variable name (UTF-16 encoded)
	data = append(data, edk2.NewStringUTF16(varName).Bytes()...)

	// Add variable data if present
	if varData != nil {
		data = append(data, varData...)
	}

	return measureSHA384(data), nil
}
