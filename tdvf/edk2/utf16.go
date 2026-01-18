package edk2

import (
	"encoding/binary"
	"unicode/utf16"
)

// StringUTF16 represents an EFI UTF-16LE encoded string.
type StringUTF16 struct {
	data []uint16
}

// NewStringUTF16 creates a new StringUTF16 from a Go string
func NewStringUTF16(s string) *StringUTF16 {
	return &StringUTF16{
		data: utf16.Encode([]rune(s)),
	}
}

// ParseUTF16 reads a null-terminated UTF-16LE string from binary data at the specified offset.
func ParseUTF16(data []byte, offset int) *StringUTF16 {
	chars := make([]uint16, 0, 32) // preallocate for typical variable names

	for pos := offset; pos+1 < len(data); pos += 2 {
		// Use binary.LittleEndian for clearer endianness handling
		char := binary.LittleEndian.Uint16(data[pos : pos+2])
		if char == 0 {
			break
		}
		chars = append(chars, char)
	}

	return &StringUTF16{data: chars}
}

// String converts to a Go string using Go's built-in UTF-16 decoder
func (s *StringUTF16) String() string {
	return string(utf16.Decode(s.data))
}

// Bytes returns the UTF-16LE bytes with null terminator
func (s *StringUTF16) Bytes() []byte {
	result := make([]byte, (len(s.data))*2)
	for i, char := range s.data {
		binary.LittleEndian.PutUint16(result[i*2:], char)
	}
	// Null terminator is already zero-initialized
	return result
}

// Size returns the number of bytes needed (including null terminator)
func (s *StringUTF16) Size() int {
	return (len(s.data) + 1) * 2
}

// TODO cleanup
// Utf16Encode converts a string to UTF-16LE bytes
// func Utf16Encode(input string) []byte {
// 	u16 := utf16.Encode([]rune(input))
// 	buf := new(bytes.Buffer)
// 	for _, r := range u16 {
// 		binary.Write(buf, binary.LittleEndian, r)
// 	}
// 	return buf.Bytes()
// }
