// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package uefi

import (
	"testing"
)

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

	s := NewUTF16(data, 0)
	expected := "Test"

	if got := s.String(); got != expected {
		t.Errorf("ParseUTF16() = %v, want %v", got, expected)
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

	s := NewUTF16(data, 4)
	expected := "Hi"

	if got := s.String(); got != expected {
		t.Errorf("ParseUTF16(offset=4) = %v, want %v", got, expected)
	}
}
