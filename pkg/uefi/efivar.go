package uefi

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gitlab.com/real-cis/cc/go-trust/pkg/guid"
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

type EfiVarList map[string]*EfiVar

// UEFI_VARIABLE_DATA structure used in TCG event logs (EV_EFI_VARIABLE_DRIVER_CONFIG).
// This is the serialized format for measuring EFI variables.
type UefiVariableData struct {
	GUID       uuid.UUID    // 16 bytes - GUID identifying the variable
	NameLength uint64       // Length of the variable name in Unicode characters
	DataLength uint64       // Length of the variable data
	Name       *StringUTF16 // UTF-16 variable name (e.g., "PK", "KEK", "db", "dbx")
	Data       []byte       // The actual variable data
}

func NewUefiVariableDataFromBytes(data []byte) (*UefiVariableData, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("data too short to be UEFI_VARIABLE_DATA")
	}

	offset := 0
	guidBytes := data[offset : offset+16]
	guidVal, err := guid.FromBytes(guidBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GUID: %v", err)
	}
	offset += 16

	nameLen := binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	dataLen := binary.LittleEndian.Uint64(data[offset : offset+8])
	offset += 8

	if offset+int(nameLen)*2+int(dataLen) > len(data) {
		return nil, fmt.Errorf("data too short for name and data lengths")
	}

	nameBytes := data[offset : offset+int(nameLen)*2]
	name := NewUTF16(nameBytes, 0)
	offset += int(nameLen) * 2

	variableData := data[offset : offset+int(dataLen)]

	return &UefiVariableData{
		GUID:       guidVal,
		NameLength: nameLen,
		DataLength: dataLen,
		Name:       name,
		Data:       variableData,
	}, nil
}

func NewUefiVariableDataFromEfiVar(efiVar *EfiVar) *UefiVariableData {
	return &UefiVariableData{
		GUID:       efiVar.GUID,
		NameLength: uint64(len(efiVar.Name.String())),
		DataLength: uint64(len(efiVar.Data)),
		Name:       efiVar.Name,
		Data:       efiVar.Data,
	}
}

// Serialize converts the UEFI_VARIABLE_DATA structure to its binary representation.
func (v *UefiVariableData) Serialize() []byte {
	var buffer []byte

	// VariableName (GUID) - 16 bytes
	buffer = append(buffer, guid.ToBytes(v.GUID)...)

	// UnicodeNameLength - 8 bytes
	nameLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nameLenBytes, v.NameLength)
	buffer = append(buffer, nameLenBytes...)

	// VariableDataLength - 8 bytes
	dataLenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(dataLenBytes, v.DataLength)
	buffer = append(buffer, dataLenBytes...)

	// UnicodeName (UTF-16 encoded)
	buffer = append(buffer, v.Name.Bytes()...)

	// VariableData
	if v.Data != nil {
		buffer = append(buffer, v.Data...)
	}

	return buffer
}

// Measure computes the SHA384 hash of the serialized UEFI_VARIABLE_DATA.
// This is used for TDX RTMR measurements.
func (v *UefiVariableData) Measure() []byte {
	hash := sha512.New384()
	hash.Write(v.Serialize())
	return hash.Sum(nil)
}
