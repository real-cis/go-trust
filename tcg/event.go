package tcg

// EventFormat represents the format of TCG event logs.
type EventFormat string

const (
	PCClientFormat  EventFormat = "tcg_pcclient"
	CanonicalFormat EventFormat = "tcg_canonical"
)

// EventType represents TCG event types as defined in the TCG PC Client specification.
type EventType uint32

const (
	EvPrebootCert          EventType = 0x0
	EvPostCode             EventType = 0x1
	EvUnused               EventType = 0x2
	EvNoAction             EventType = 0x3
	EvSeparator            EventType = 0x4
	EvAction               EventType = 0x5
	EvEventTag             EventType = 0x6
	EvSCrtmContents        EventType = 0x7
	EvSCrtmVersion         EventType = 0x8
	EvCPUMicrocode         EventType = 0x9
	EvPlatformConfigFlags  EventType = 0xa
	EvTableOfDevices       EventType = 0xb
	EvCompactHash          EventType = 0xc
	EvIPL                  EventType = 0xd
	EvIPLPartitionData     EventType = 0xe
	EvNonhostCode          EventType = 0xf
	EvNonhostConfig        EventType = 0x10
	EvNonhostInfo          EventType = 0x11
	EvOmitBootDeviceEvents EventType = 0x12
	EvPostCode2            EventType = 0x13
	EvIMAMeasurementEvent  EventType = 0x14

	EvEfiEventBase               EventType = 0x80000000
	EvEfiVariableDriverConfig    EventType = 0x80000001
	EvEfiVariableBoot            EventType = 0x80000002
	EvEfiBootServicesApplication EventType = 0x80000003
	EvEfiBootServicesDriver      EventType = 0x80000004
	EvEfiRuntimeServicesDriver   EventType = 0x80000005
	EvEfiGPTEvent                EventType = 0x80000006
	EvEfiAction                  EventType = 0x80000007
	EvEfiPlatformFirmwareBlob    EventType = 0x80000008
	EvEfiHandoffTables           EventType = 0x80000009
	EvEfiPlatformFirmwareBlob2   EventType = 0x8000000a
	EvEfiHandoffTables2          EventType = 0x8000000b
	EvEfiVariableBoot2           EventType = 0x8000000c
	EvEfiGPTEvent2               EventType = 0x8000000d
	EvEfiHCRTMEvent              EventType = 0x80000010
	EvEfiVariableAuthority       EventType = 0x800000e0
	EvEfiSPDMFirmwareBlob        EventType = 0x800000e1
	EvEfiSPDMFirmwareConfig      EventType = 0x800000e2
	EvEfiSPDMDevicePolicy        EventType = 0x800000e3
	EvEfiSPDMDeviceAuthority     EventType = 0x800000e4
)

func (t EventType) String() string {
	switch t {
	case EvPrebootCert:
		return "EV_PREBOOT_CERT"
	case EvPostCode:
		return "EV_POST_CODE"
	case EvUnused:
		return "EV_UNUSED"
	case EvNoAction:
		return "EV_NO_ACTION"
	case EvSeparator:
		return "EV_SEPARATOR"
	case EvAction:
		return "EV_ACTION"
	case EvEventTag:
		return "EV_EVENT_TAG"
	case EvSCrtmContents:
		return "EV_S_CRTM_CONTENTS"
	case EvSCrtmVersion:
		return "EV_S_CRTM_VERSION"
	case EvCPUMicrocode:
		return "EV_CPU_MICROCODE"
	case EvPlatformConfigFlags:
		return "EV_PLATFORM_CONFIG_FLAGS"
	case EvTableOfDevices:
		return "EV_TABLE_OF_DEVICES"
	case EvCompactHash:
		return "EV_COMPACT_HASH"
	case EvIPL:
		return "EV_IPL"
	case EvIPLPartitionData:
		return "EV_IPL_PARTITION_DATA"
	case EvNonhostCode:
		return "EV_NONHOST_CODE"
	case EvNonhostConfig:
		return "EV_NONHOST_CONFIG"
	case EvNonhostInfo:
		return "EV_NONHOST_INFO"
	case EvOmitBootDeviceEvents:
		return "EV_OMIT_BOOT_DEVICE_EVENTS"
	case EvPostCode2:
		return "EV_POST_CODE2"
	case EvIMAMeasurementEvent:
		return "IMA_MEASUREMENT_EVENT"
	case EvEfiEventBase:
		return "EV_EFI_EVENT_BASE"
	case EvEfiVariableDriverConfig:
		return "EV_EFI_VARIABLE_DRIVER_CONFIG"
	case EvEfiVariableBoot:
		return "EV_EFI_VARIABLE_BOOT"
	case EvEfiBootServicesApplication:
		return "EV_EFI_BOOT_SERVICES_APPLICATION"
	case EvEfiBootServicesDriver:
		return "EV_EFI_BOOT_SERVICES_DRIVER"
	case EvEfiRuntimeServicesDriver:
		return "EV_EFI_RUNTIME_SERVICES_DRIVER"
	case EvEfiGPTEvent:
		return "EV_EFI_GPT_EVENT"
	case EvEfiAction:
		return "EV_EFI_ACTION"
	case EvEfiPlatformFirmwareBlob:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB"
	case EvEfiHandoffTables:
		return "EV_EFI_HANDOFF_TABLES"
	case EvEfiPlatformFirmwareBlob2:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
	case EvEfiHandoffTables2:
		return "EV_EFI_HANDOFF_TABLES2"
	case EvEfiVariableBoot2:
		return "EV_EFI_VARIABLE_BOOT2"
	case EvEfiGPTEvent2:
		return "EV_EFI_GPT_EVENT2"
	case EvEfiHCRTMEvent:
		return "EV_EFI_HCRTM_EVENT"
	case EvEfiVariableAuthority:
		return "EV_EFI_VARIABLE_AUTHORITY"
	case EvEfiSPDMFirmwareBlob:
		return "EV_EFI_SPDM_FIRMWARE_BLOB"
	case EvEfiSPDMFirmwareConfig:
		return "EV_EFI_SPDM_FIRMWARE_CONFIG"
	case EvEfiSPDMDevicePolicy:
		return "EV_EFI_SPDM_DEVICE_POLICY"
	case EvEfiSPDMDeviceAuthority:
		return "EV_EFI_SPDM_DEVICE_AUTHORITY"
	}
	return ""
}
