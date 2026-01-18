package tdvf

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"

	"gitlab.com/real-cis/cc/go-trust/tdvf/edk2"
	"gitlab.com/real-cis/cc/go-trust/tdvf/mrtd"
)

type TDVFMeasurements struct {
	MRTD       []byte
	SecureBoot SecureBootVars
}

type SecureBootVars struct {
	PK  []byte
	KEK []byte
	DB  []byte
	DBX []byte
}

func ParseFirmware(filename string) (*TDVFMeasurements, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	mrtdHash := mrtd.BuildMRTD(data, false)

	sbVars, err := ParseSecureBootVariables(data, filename)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secure boot variables: %w", err)
	}

	return &TDVFMeasurements{
		MRTD:       mrtdHash,
		SecureBoot: *sbVars,
	}, nil
}

// TODO cleanup, make library compatible
func ParseSecureBootVariables(data []byte, filename string) (*SecureBootVars, error) {
	// Probe file
	offset := edk2.FindNvData(data)
	if offset == -1 {
		return nil, fmt.Errorf("not a valid EDK2 variable store file")
	}

	// Parse variable store
	store, err := edk2.NewEdk2VarStoreFromBytes(data, filename)
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
			fmt.Printf(" [%s]", joinStrings(attrs, ","))
		}
		fmt.Println()

		fmt.Printf("  Count:      %d\n", evar.Count)
		fmt.Printf("  PkIdx:      %d\n", evar.PkIdx)
		fmt.Printf("  Time:       %s\n", evar.Time.Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("  Data size:  %d bytes\n", len(evar.Data))

		// if *showData && len(evar.Data) > 0 {
		// 	dataLen := len(evar.Data)
		// 	if dataLen > *maxDataLen {
		// 		dataLen = *maxDataLen
		// 	}
		// 	fmt.Printf("  Data:\n")
		// 	fmt.Printf("%s", hexDump(evar.Data[:dataLen], 4))
		// 	if dataLen < len(evar.Data) {
		// 		fmt.Printf("    ... (%d more bytes)\n", len(evar.Data)-dataLen)
		// 	}
		// }

		var measurement []byte
		switch name {
		case "PK":
			measurement, err = MeasureTdxEfiVariable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "PK", evar.Data)
			if err == nil {
				sbVars.PK = measurement
			}
		case "KEK":
			measurement, err = MeasureTdxEfiVariable("8BE4DF61-93CA-11D2-AA0D-00E098032B8C", "KEK", evar.Data)
			if err == nil {
				sbVars.KEK = measurement
			}
		case "db":
			measurement, err = MeasureTdxEfiVariable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "db", evar.Data)
			if err == nil {
				sbVars.DB = measurement
			}
		case "dbx":
			measurement, err = MeasureTdxEfiVariable("D719B2CB-3D3A-4596-A3BC-DAD00E67656F", "dbx", evar.Data)
			if err == nil {
				sbVars.DBX = measurement
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to measure variable %s: %v", name, err)
		}
		if measurement != nil {
			fmt.Printf("  Measurement: %s\n", hex.EncodeToString(measurement))
		}

		fmt.Println()
	}

	return sbVars, nil
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

func hexDump(data []byte, indent int) string {
	indentStr := ""
	for i := 0; i < indent; i++ {
		indentStr += " "
	}

	result := ""
	for i := 0; i < len(data); i += 16 {
		result += indentStr
		result += fmt.Sprintf("%04x: ", i)

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result += fmt.Sprintf("%02x ", data[i+j])
			} else {
				result += "   "
			}
			if j == 7 {
				result += " "
			}
		}

		result += " |"

		// ASCII representation
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				b := data[i+j]
				if b >= 32 && b <= 126 {
					result += string(b)
				} else {
					result += "."
				}
			}
		}
		result += "|\n"
	}

	return result
}
