// Package guid provides unified GUID handling for TDX and UEFI formats.
package guid

import (
	"fmt"

	"github.com/google/uuid"
)

// Common constants
const (
	GUIDStringLen = 36
)

// Parse parses a GUID string (standard format).
func Parse(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// MustParse parses a GUID string or panics.
func MustParse(s string) uuid.UUID {
	return uuid.MustParse(s)
}

// FromBytes parses a GUID from EFI binary data (Little Endian for first 3 fields, Big Endian/Raw for rest).
// This expects at least 16 bytes in data using 0-based indexing.
func FromBytes(data []byte) (uuid.UUID, error) {
	if len(data) < 16 {
		return uuid.Nil, fmt.Errorf("insufficient data for GUID")
	}

	var g uuid.UUID
	// Read and reverse Data1 (4 bytes)
	g[0] = data[3]
	g[1] = data[2]
	g[2] = data[1]
	g[3] = data[0]

	// Read and reverse Data2 (2 bytes)
	g[4] = data[5]
	g[5] = data[4]

	// Read and reverse Data3 (2 bytes)
	g[6] = data[7]
	g[7] = data[6]

	// Read Data4 (8 bytes) as-is
	copy(g[8:16], data[8:16])

	return g, nil
}

// ToBytes converts a UUID to EFI binary format (Little Endian for first 3 fields).
func ToBytes(g uuid.UUID) []byte {
	res := make([]byte, 16)

	// Write reversed Data1
	res[0] = g[3]
	res[1] = g[2]
	res[2] = g[1]
	res[3] = g[0]

	// Write reversed Data2
	res[4] = g[5]
	res[5] = g[4]

	// Write reversed Data3
	res[6] = g[7]
	res[7] = g[6]

	// Write Data4 as-is
	copy(res[8:], g[8:])

	return res
}
