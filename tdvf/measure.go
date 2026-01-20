package tdvf

import (
	"crypto/sha512"
	"encoding/binary"

	"gitlab.com/real-cis/cc/go-trust/internal/guid"
	"gitlab.com/real-cis/cc/go-trust/tdvf/edk2"
)

// represents an EFI variable with TDX measurement capabilities.
type TdxEfiVariable struct {
	*edk2.EfiVar
}

func NewTdxEfiVariable(efiVar *edk2.EfiVar) *TdxEfiVariable {
	return &TdxEfiVariable{EfiVar: efiVar}
}

// measurement (SHA384 hash) of the EFI variable.
// The measurement includes: GUID (16 bytes) + name length (8 bytes) +
// data size (8 bytes) + UTF-16 name + data
func (v *TdxEfiVariable) Measure() ([]byte, error) {
	var buffer []byte

	buffer = append(buffer, guid.ToBytes(v.GUID)...)

	// Variable name length
	nameLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nameLenBytes, uint64(len(v.Name.String())))
	buffer = append(buffer, nameLenBytes...)

	// Variable data size
	dataSizeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(dataSizeBytes, uint64(len(v.Data)))
	buffer = append(buffer, dataSizeBytes...)

	// Add variable name (UTF-16 encoded)
	buffer = append(buffer, v.Name.Bytes()...)

	if v.Data != nil {
		buffer = append(buffer, v.Data...)
	}

	hash := sha512.New384()
	hash.Write(buffer)
	return hash.Sum(nil), nil
}
