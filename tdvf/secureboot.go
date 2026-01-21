package tdvf

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"gitlab.com/real-cis/cc/go-trust/internal/guid"
	"gitlab.com/real-cis/cc/go-trust/tdvf/edk2"
)

// SecureBootVars contains the measurements of UEFI Secure Boot variables.
type SecureBootVars struct {
	PK  []byte
	KEK []byte
	DB  []byte
	DBX []byte
}

// TdxEfiVariable represents an EFI variable with TDX measurement capabilities.
type TdxEfiVariable struct {
	*edk2.EfiVar
}

// NewTdxEfiVariable creates a new TdxEfiVariable from an EfiVar.
func NewTdxEfiVariable(efiVar *edk2.EfiVar) *TdxEfiVariable {
	return &TdxEfiVariable{EfiVar: efiVar}
}

// Measure computes the SHA384 measurement of the EFI variable.
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

// MeasureSecureBootVariables parses secure boot variables from firmware data
// and returns their measurements.
func MeasureSecureBootVariables(data []byte) (*SecureBootVars, error) {
	// Probe file
	offset := edk2.FindNvData(data)
	if offset == -1 {
		return nil, fmt.Errorf("not a valid EDK2 variable store file")
	}

	// Parse variable store
	store, err := edk2.NewEdk2VarStore(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse variable store: %v", err)
	}

	// Get variables
	varList, err := store.GetVarList()
	if err != nil {
		return nil, fmt.Errorf("failed to get variable list: %v", err)
	}
	fmt.Printf("varlist %v\n", varList)

	// Sort variable names for consistent output
	names := make([]string, 0, len(varList))
	for name := range varList {
		names = append(names, name)
	}
	sort.Strings(names)

	// Display variables
	fmt.Printf("Found %d variables:\n\n", len(varList))

	sbVars := &SecureBootVars{}

	for _, name := range names {
		evar := varList[name]
		fmt.Printf("Variable: %s\n", name)
		fmt.Printf("  GUID:       %s\n", edk2.GUIDName(evar.GUID))
		fmt.Printf("  GUID (raw): %s\n", evar.GUID.String())
		fmt.Printf("  Attributes: 0x%08x", evar.Attr)

		// Decode attributes
		attrs := []string{}
		if evar.Attr&edk2.EFI_VARIABLE_NON_VOLATILE != 0 {
			attrs = append(attrs, "NV")
		}
		if evar.Attr&edk2.EFI_VARIABLE_BOOTSERVICE_ACCESS != 0 {
			attrs = append(attrs, "BS")
		}
		if evar.Attr&edk2.EFI_VARIABLE_RUNTIME_ACCESS != 0 {
			attrs = append(attrs, "RT")
		}
		if evar.Attr&edk2.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0 {
			attrs = append(attrs, "AT")
		}
		if len(attrs) > 0 {
			fmt.Printf(" %s", attrs)
		}

		var measurement []byte
		switch name {
		case "PK":
			tdxVar := NewTdxEfiVariable(evar)
			measurement, err = tdxVar.Measure()
			if err == nil {
				sbVars.PK = measurement
			}
		case "KEK":
			tdxVar := NewTdxEfiVariable(evar)
			measurement, err = tdxVar.Measure()
			if err == nil {
				sbVars.KEK = measurement
			}
		case "db":
			tdxVar := NewTdxEfiVariable(evar)
			measurement, err = tdxVar.Measure()
			if err == nil {
				sbVars.DB = measurement
			}
		case "dbx":
			tdxVar := NewTdxEfiVariable(evar)
			measurement, err = tdxVar.Measure()
			if err == nil {
				sbVars.DBX = measurement
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to measure variable %s: %v", name, err)
		}
		fmt.Println()

		fmt.Printf("  Count:      %d\n", evar.Count)
		fmt.Printf("  PkIdx:      %d\n", evar.PkIdx)
		fmt.Printf("  Time:       %s\n", evar.Time.Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("  Data size:  %d bytes\n", len(evar.Data))

		if measurement != nil {
			fmt.Printf("  Measurement: %s\n", hex.EncodeToString(measurement))
		}

		fmt.Println()
	}

	return sbVars, nil
}
