// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package edk2

import (
	"testing"
)

func TestFindNvData(t *testing.T) {
	// test data with NvData GUID at offset 1024+16
	data := make([]byte, 2048)

	// Place NvData GUID at offset 1024+16
	// We need to write the GUID bytes in the same format as ParseGUIDBin expects
	offset := 1024 + 16

	// Use the actual GUID bytes from GUIDNvData
	guidBytes := make([]byte, 16)
	// Standard UUID format for "fff12b8d-7696-4c8b-a985-2747075b4f50"
	// The ParseGUIDBin function reads these as little-endian for first 3 fields
	guidBytes[0] = 0x8d
	guidBytes[1] = 0x2b
	guidBytes[2] = 0xf1
	guidBytes[3] = 0xff
	guidBytes[4] = 0x96
	guidBytes[5] = 0x76
	guidBytes[6] = 0x8b
	guidBytes[7] = 0x4c
	guidBytes[8] = 0xa9
	guidBytes[9] = 0x85
	guidBytes[10] = 0x27
	guidBytes[11] = 0x47
	guidBytes[12] = 0x07
	guidBytes[13] = 0x5b
	guidBytes[14] = 0x4f
	guidBytes[15] = 0x50

	copy(data[offset:], guidBytes)

	result := FindNvData(data)
	expected := 1024

	if result != expected {
		// Debug: let's see what GUID was actually parsed
		if result == -1 {
			t.Logf("GUID not found - checking what's at offset 1024+16")
			if parsed, err := ParseGUIDBin(data, offset); err == nil {
				t.Logf("Parsed GUID: %s", parsed.String())
				t.Logf("Expected GUID: %s", GUIDNvData.String())
			}
		}
		t.Errorf("FindNvData() = %d, want %d", result, expected)
	}
}

func TestFindNvDataNotFound(t *testing.T) {
	// Create test data without NvData GUID
	data := make([]byte, 2048)

	result := FindNvData(data)
	expected := -1

	if result != expected {
		t.Errorf("FindNvData() = %d, want %d", result, expected)
	}
}

func TestGUIDName(t *testing.T) {
	tests := []struct {
		name     string
		guid     string
		expected string
	}{
		{
			name:     "NvData GUID",
			guid:     "fff12b8d-7696-4c8b-a985-2747075b4f50",
			expected: "guid:NvData",
		},
		{
			name:     "AuthVars GUID",
			guid:     "aaf32c78-947b-439a-a180-2e144ec37792",
			expected: "guid:AuthVars",
		},
		{
			name:     "Unknown GUID",
			guid:     "00000000-0000-0000-0000-000000000000",
			expected: "00000000-0000-0000-0000-000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guid, err := ParseGUID(tt.guid)
			if err != nil {
				t.Fatalf("Failed to parse GUID %s: %v", tt.guid, err)
			}
			result := GUIDName(guid)
			if result != tt.expected {
				t.Errorf("GUIDName(%s) = %s, want %s", tt.guid, result, tt.expected)
			}
		})
	}
}
