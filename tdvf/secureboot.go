package tdvf

import (
	"encoding/hex"
	"fmt"
	"log"
	"sort"

	"gitlab.com/real-cis/cc/go-trust/internal/uefi"
	"gitlab.com/real-cis/cc/go-trust/tdvf/edk2"
)

// SecureBootVars contains the measurements of UEFI Secure Boot variables.
type SecureBootVars struct {
	PK  []byte
	KEK []byte
	DB  []byte
	DBX []byte
}

// parses and measures secure boot variables from firmware data
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
	log.Printf("varlist %v\n", varList)

	// Sort variable names for consistent output
	names := make([]string, 0, len(varList))
	for name := range varList {
		names = append(names, name)
	}
	sort.Strings(names)

	// Display variables
	log.Printf("Found %d variables:\n\n", len(varList))

	sbVars := &SecureBootVars{}

	for _, name := range names {
		evar := varList[name]
		log.Printf("Variable: %s\n", name)
		log.Printf("  GUID:       %s\n", edk2.GUIDName(evar.GUID))
		log.Printf("  GUID (raw): %s\n", evar.GUID.String())
		log.Printf("  Attributes: 0x%08x", evar.Attr)

		// Decode attributes
		attrs := []string{}
		if evar.Attr&uefi.EFI_VARIABLE_NON_VOLATILE != 0 {
			attrs = append(attrs, "NV")
		}
		if evar.Attr&uefi.EFI_VARIABLE_BOOTSERVICE_ACCESS != 0 {
			attrs = append(attrs, "BS")
		}
		if evar.Attr&uefi.EFI_VARIABLE_RUNTIME_ACCESS != 0 {
			attrs = append(attrs, "RT")
		}
		if evar.Attr&uefi.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0 {
			attrs = append(attrs, "AT")
		}
		if len(attrs) > 0 {
			log.Printf(" %s", attrs)
		}

		var measurement []byte
		switch name {
		case "PK":
			varData := uefi.NewUefiVariableDataFromEfiVar(evar)
			measurement = varData.Measure()
			sbVars.PK = measurement
		case "KEK":
			varData := uefi.NewUefiVariableDataFromEfiVar(evar)
			measurement = varData.Measure()
			sbVars.KEK = measurement
		case "db":
			varData := uefi.NewUefiVariableDataFromEfiVar(evar)
			measurement = varData.Measure()
			sbVars.DB = measurement
		case "dbx":
			varData := uefi.NewUefiVariableDataFromEfiVar(evar)
			measurement = varData.Measure()
			sbVars.DBX = measurement
		}

		log.Printf("  Count:      %d\n", evar.Count)
		log.Printf("  PkIdx:      %d\n", evar.PkIdx)
		log.Printf("  Time:       %s\n", evar.Time.Format("2006-01-02 15:04:05 MST"))
		log.Printf("  Data size:  %d bytes\n", len(evar.Data))

		if measurement != nil {
			log.Printf("  Measurement: %s\n", hex.EncodeToString(measurement))
		}
	}

	return sbVars, nil
}
