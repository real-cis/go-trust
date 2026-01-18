package edk2

import (
	"testing"
)

func TestStringUTF16(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantStr string
	}{
		{
			name:    "Simple ASCII",
			input:   "Hello",
			wantStr: "Hello",
		},
		{
			name:    "Empty string",
			input:   "",
			wantStr: "",
		},
		{
			name:    "Variable name",
			input:   "SecureBoot",
			wantStr: "SecureBoot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewStringUTF16(tt.input)

			// Test String() method
			if got := s.String(); got != tt.wantStr {
				t.Errorf("String() = %v, want %v", got, tt.wantStr)
			}

			// Test Size() method
			expectedSize := (len([]rune(tt.input)) + 1) * 2
			if got := s.Size(); got != expectedSize {
				t.Errorf("Size() = %v, want %v", got, expectedSize)
			}

			// TODO: Fix
			// Test Bytes() method - should end with null terminator
			// bytes := s.Bytes()
			// if len(bytes) < 2 {
			// 	t.Errorf("Bytes() length = %v, want at least 2", len(bytes))
			// }
			// if bytes[len(bytes)-1] != 0 || bytes[len(bytes)-2] != 0 {
			// 	t.Errorf("Bytes() should end with null terminator")
			// }
		})
	}
}

func TestParseUTF16(t *testing.T) {
	// Create UTF-16 encoded "Test" string with null terminator
	// T=0x0054, e=0x0065, s=0x0073, t=0x0074
	data := []byte{
		0x54, 0x00, // T
		0x65, 0x00, // e
		0x73, 0x00, // s
		0x74, 0x00, // t
		0x00, 0x00, // null terminator
	}

	s := ParseUTF16(data, 0)
	expected := "Test"

	if got := s.String(); got != expected {
		t.Errorf("ParseUCS16() = %v, want %v", got, expected)
	}
}

func TestParseUTF16WithOffset(t *testing.T) {
	// Create data with UTF-16 string at offset 4
	data := make([]byte, 20)
	// Add "Hi" at offset 4
	data[4] = 0x48 // H
	data[5] = 0x00
	data[6] = 0x69 // i
	data[7] = 0x00
	data[8] = 0x00 // null
	data[9] = 0x00

	s := ParseUTF16(data, 4)
	expected := "Hi"

	if got := s.String(); got != expected {
		t.Errorf("ParseUCS16(offset=4) = %v, want %v", got, expected)
	}
}
