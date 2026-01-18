package edk2

import (
	"encoding/binary"
	"time"

	"github.com/google/uuid"
)

// Variable attributes
const (
	EFI_VARIABLE_NON_VOLATILE                          = 0x00000001
	EFI_VARIABLE_BOOTSERVICE_ACCESS                    = 0x00000002
	EFI_VARIABLE_RUNTIME_ACCESS                        = 0x00000004
	EFI_VARIABLE_HARDWARE_ERROR_RECORD                 = 0x00000008
	EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            = 0x00000010 // deprecated
	EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020
	EFI_VARIABLE_APPEND_WRITE                          = 0x00000040
)

// EfiVar represents an EFI variable
type EfiVar struct {
	Name  *StringUTF16
	GUID  uuid.UUID
	Attr  uint32
	Data  []byte
	Count uint64
	PkIdx uint32
	Time  time.Time
}

func NewEfiVar(name *StringUTF16, guid uuid.UUID, attr uint32, data []byte, count uint64, pkIdx uint32) *EfiVar {
	return &EfiVar{
		Name:  name,
		GUID:  guid,
		Attr:  attr,
		Data:  data,
		Count: count,
		PkIdx: pkIdx,
	}
}

// ParseTime parses the timestamp from the variable data
func (v *EfiVar) ParseTime(data []byte, offset int) error {
	if offset+16 > len(data) {
		// No valid timestamp
		return nil
	}

	// EFI_TIME structure:
	// UINT16 Year
	// UINT8 Month
	// UINT8 Day
	// UINT8 Hour
	// UINT8 Minute
	// UINT8 Second
	// UINT8 Pad1
	// UINT32 Nanosecond
	// INT16 TimeZone
	// UINT8 Daylight
	// UINT8 Pad2

	year := binary.LittleEndian.Uint16(data[offset : offset+2])
	month := data[offset+2]
	day := data[offset+3]
	hour := data[offset+4]
	minute := data[offset+5]
	second := data[offset+6]
	// Skip pad1
	nanosecond := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
	// timezone := int16(binary.LittleEndian.Uint16(data[offset+12 : offset+14]))
	// daylight := data[offset+14]
	// Skip pad2

	// Create time in UTC
	v.Time = time.Date(int(year), time.Month(month), int(day),
		int(hour), int(minute), int(second), int(nanosecond), time.UTC)

	return nil
}

// EfiVarList is a map of variable names to EfiVar
type EfiVarList map[string]*EfiVar
