package edk2

import (
	"fmt"

	"github.com/google/uuid"
	"gitlab.com/real-cis/cc/go-trust/internal/guid"
)

// Common GUID constants
var (
	GUIDFfs                        = uuid.MustParse("8c8ce578-8a3d-4f1c-9935-896185c32dd3")
	GUIDNvData                     = uuid.MustParse("fff12b8d-7696-4c8b-a985-2747075b4f50")
	GUIDAuthVars                   = uuid.MustParse("aaf32c78-947b-439a-a180-2e144ec37792")
	GUIDEfiGlobalVariable          = uuid.MustParse("8be4df61-93ca-11d2-aa0d-00e098032b8c")
	GUIDEfiImageSecurityDatabase   = uuid.MustParse("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
	GUIDEfiSecureBootEnableDisable = uuid.MustParse("f0a30bc7-af08-4556-99c4-001009c93a44")
	GUIDEfiCustomModeEnable        = uuid.MustParse("c076ec0c-7028-4399-a072-71ee5c448b9f")
	GUIDMicrosoftVendor            = uuid.MustParse("77fa9abd-0359-4d32-bd60-28f4e78f784b")
	GUIDShim                       = uuid.MustParse("605dab50-e046-4300-abb6-3dd810dd8b23")
)

// GUID name mapping
var guidNameTable = map[uuid.UUID]string{
	// Firmware volumes
	GUIDFfs:      "Ffs",
	GUIDNvData:   "NvData",
	GUIDAuthVars: "AuthVars",
	uuid.MustParse("ee4e5898-3914-4259-9d6e-dc7bd79403cf"): "LzmaCompress",
	uuid.MustParse("1ba0062e-c779-4582-8566-336ae8f78f09"): "ResetVector",

	// Variable types
	GUIDEfiGlobalVariable:          "EfiGlobalVariable",
	GUIDEfiImageSecurityDatabase:   "EfiImageSecurityDatabase",
	GUIDEfiSecureBootEnableDisable: "EfiSecureBootEnableDisable",
	GUIDEfiCustomModeEnable:        "EfiCustomModeEnable",

	// Signature owner
	GUIDMicrosoftVendor: "MicrosoftVendor",
	GUIDShim:            "Shim",
}

// ParseGUIDBin parses a GUID from binary data at the specified offset
// Note: GUID is stored in little-endian format in EFI (first 3 fields are LE, rest are as-is)
func ParseGUIDBin(data []byte, offset int) (uuid.UUID, error) {
	if offset+16 > len(data) {
		return uuid.Nil, fmt.Errorf("insufficient data for GUID at offset %d", offset)
	}
	return guid.FromBytes(data[offset : offset+16])
}

// GUIDName returns a human-readable name for a GUID if known, otherwise returns the GUID string
func GUIDName(guid uuid.UUID) string {
	if name, ok := guidNameTable[guid]; ok {
		return fmt.Sprintf("guid:%s", name)
	}
	return guid.String()
}

func ParseGUID(s string) (uuid.UUID, error) {
	guid, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, err
	}
	return guid, nil
}
