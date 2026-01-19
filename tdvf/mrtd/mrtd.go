package mrtd

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"gitlab.com/real-cis/cc/go-trust/internal/guid"
)

// TDX Metadata constants
const (
	TDXMetadataGUIDStr                    = "e9eaf9f3-168e-44d5-a8eb-7f4d8738f6ae"
	TdxMetadataGuidSize                   = 16
	TdxMetadataDescriptorSize             = 16
	TdxMetadataSectionSize                = 32
	TDXMetadataSignature                  = 0x46564454
	TDXMetadataSectionTypeTDInfo          = 7
	TDXMetadataSectionTypeMax             = 9
	TDXMetadataAttributesExtendMR         = 0x00000001
	TDXMetadataAttributesExtendMemPageAdd = 0x00000002

	// Memory and buffer constants
	PageSize = 0x1000

	// Offset and size constants
	TDVFDescriptorOffset      = 0x20
	OVMFTableFooterGUIDOffset = 0x30
	SHA384DigestSize          = 0x30
)

var (
	OVMFTableFooterGUID      = guid.MustParse("96b582de-1fb2-45f7-baea-a366c55a082d")
	OVMFTableTDXMetadataGUID = guid.MustParse("e47a6535-984a-4798-865e-4685a7bf8ec2")
)

// TdxMetadataDescriptor represents the TDX metadata descriptor
type TdxMetadataDescriptor struct {
	Signature            uint32
	Length               uint32
	Version              uint32
	NumberOfSectionEntry uint32
}

func (t *TdxMetadataDescriptor) IsValid() bool {
	if t.Signature != TDXMetadataSignature {
		return false
	}

	length := t.Length
	if t.Version != 1 ||
		t.NumberOfSectionEntry == 0 ||
		length < 16 ||
		(length-16)%32 != 0 ||
		(length-16)/32 != t.NumberOfSectionEntry {
		return false
	}

	return true
}

// TdxMetadataSection represents a TDX metadata section
type TdxMetadataSection struct {
	DataOffset     uint32
	RawDataSize    uint32
	MemoryAddress  uint64
	MemoryDataSize uint64
	Type           uint32
	Attributes     uint32
}

// findMetadataOffset locates the TDX metadata offset in the image file
func findMetadataOffset(data []byte) uint32 {
	imageSize := uint64(len(data))
	// Check for OVMF table footer GUID
	footerGuidBuf := make([]byte, 16)
	copy(footerGuidBuf, data[imageSize-OVMFTableFooterGUIDOffset:imageSize-OVMFTableFooterGUIDOffset+16])

	if bytes.Equal(guid.ToBytes(OVMFTableFooterGUID), footerGuidBuf) {
		return findMetadataOffsetFromOvmfTable(data)
	} else {
		// Try TDVF descriptor approach
		return findMetadataOffsetFromTdvfDescriptor(data)
	}
}

// finds metadata offset using OVMF table
func findMetadataOffsetFromOvmfTable(data []byte) uint32 {
	imageSize := uint64(len(data))
	offset := imageSize - OVMFTableFooterGUIDOffset

	var tableLen uint16
	r := bytes.NewReader(data[offset:])
	binary.Read(r, binary.LittleEndian, &tableLen)

	tableLen -= 16 + uint16(unsafe.Sizeof(uint16(0)))

	ovmfTableOffset := imageSize - OVMFTableFooterGUIDOffset - uint64(unsafe.Sizeof(uint16(0)))

	var count uint16 = 0
	for count < tableLen {
		guidBuf := data[ovmfTableOffset-16 : ovmfTableOffset]

		var length uint16
		binary.LittleEndian.Uint16(data[ovmfTableOffset-16-2:])
		length = binary.LittleEndian.Uint16(data[ovmfTableOffset-16-2 : ovmfTableOffset-16])

		if bytes.Equal(guid.ToBytes(OVMFTableTDXMetadataGUID), guidBuf) {
			metadataOffsetOffset := ovmfTableOffset - 16 - 2 - 4
			offsetVal := binary.LittleEndian.Uint32(data[metadataOffsetOffset : metadataOffsetOffset+4])
			return uint32(imageSize) - offsetVal - TdxMetadataGuidSize
		}
		ovmfTableOffset -= uint64(length)
		count += length
	}

	return 0 // If not found
}

// findMetadataOffsetFromTdvfDescriptor finds metadata offset using TDVF descriptor
func findMetadataOffsetFromTdvfDescriptor(data []byte) uint32 {
	imageSize := len(data)
	offset := imageSize - TDVFDescriptorOffset

	val := binary.LittleEndian.Uint32(data[offset : offset+4])
	return val - TdxMetadataGuidSize
}

// readMetadataDescriptor reads the metadata descriptor from the file at the given offset
func readMetadataDescriptor(data []byte, metadataOffset uint32) (TdxMetadataDescriptor, error) {
	if metadataOffset >= uint32(len(data)) {
		return TdxMetadataDescriptor{}, fmt.Errorf("offset out of bounds")
	}

	descOffset := metadataOffset + TdxMetadataGuidSize
	// metadataOffset points to GUID + Descriptor.
	// We want to skip GUID.

	if uint64(descOffset)+uint64(TdxMetadataDescriptorSize) > uint64(len(data)) {
		return TdxMetadataDescriptor{}, fmt.Errorf("descriptor out of bounds")
	}

	descBytes := data[descOffset : descOffset+uint32(TdxMetadataDescriptorSize)]
	var descriptor TdxMetadataDescriptor
	reader := bytes.NewReader(descBytes)
	binary.Read(reader, binary.LittleEndian, &descriptor)

	if !descriptor.IsValid() {
		return descriptor, fmt.Errorf("invalid descriptor")
	}

	return descriptor, nil
}

// processSections processes the metadata sections and builds the MRTD hash
func processSections(data []byte, metadataOffset uint32,
	descriptor TdxMetadataDescriptor, qemuCompat bool) ([]byte, error) {
	// Metadata buffer starts after GUID
	start := metadataOffset + TdxMetadataGuidSize
	if uint64(start)+uint64(descriptor.Length) > uint64(len(data)) {
		return nil, fmt.Errorf("metadata buffer out of bounds")
	}

	metadataBuf := data[start : start+descriptor.Length]

	var buffer128 [MRTDExtensionBufferSize]byte // used by page add
	var buffer256 [TDHMRExtendGranularity]byte  // used by mr extend
	hasher := sha512.New384()                   // SHA-384 hasher

	// Process each section
	for i := range descriptor.NumberOfSectionEntry {
		secOffset := TdxMetadataDescriptorSize + i*TdxMetadataSectionSize

		var sec TdxMetadataSection
		secReader := bytes.NewReader(metadataBuf[secOffset:])
		binary.Read(secReader, binary.LittleEndian, &sec)

		if err := validateSection(&sec); err != nil {
			return nil, err
		}
		if qemuCompat {
			processSectionQemu(data, &sec, &buffer128, &buffer256, hasher)
		} else {
			processSection(data, &sec, &buffer128, &buffer256, hasher)
		}
	}

	// Get final hash
	return hasher.Sum(nil), nil
}

// validateSection validates a metadata section
func validateSection(sec *TdxMetadataSection) error {
	// Sanity checks
	if sec.MemoryAddress%PageSize != 0 {
		return fmt.Errorf("memory address must be 4K aligned")
	}

	if (sec.Type != TDXMetadataSectionTypeTDInfo) &&
		(sec.MemoryAddress != 0 || sec.MemoryDataSize != 0) &&
		sec.MemoryDataSize < uint64(sec.RawDataSize) {
		return fmt.Errorf("memory data size must exceed or equal the raw data size")
	}

	if sec.MemoryDataSize%PageSize != 0 {
		return fmt.Errorf("memory data size must be 4K aligned")
	}

	if sec.Type >= TDXMetadataSectionTypeMax {
		return fmt.Errorf("invalid type value: %d", sec.Type)
	}

	return nil
}

// processSection processes a single metadata section
// Default spec is to MEM_PAGE_ADD followed by MR.EXTEND per page (4K)
func processSection(data []byte, sec *TdxMetadataSection,
	buffer128 *[MRTDExtensionBufferSize]byte,
	buffer256 *[TDHMRExtendGranularity]byte, hasher io.Writer) {
	fmt.Printf("Processing section type: %d \n", sec.Type)

	nrPages := sec.MemoryDataSize / PageSize

	// Process memory pages
	for iter := range nrPages {
		if sec.Attributes&TDXMetadataAttributesExtendMemPageAdd == 0 {
			// Use TDCALL [TDH.MEM.PAGE.ADD]
			fillBufferWithMemPageAdd(buffer128, sec.MemoryAddress+iter*PageSize)
			hasher.Write(buffer128[:])
		}

		// Process MR.EXTEND
		if sec.Attributes&TDXMetadataAttributesExtendMR != 0 {
			// Use TDCALL [TDH.MR.EXTEND]
			granularity := uint64(TDHMRExtendGranularity)
			iteration := PageSize / granularity
			for chunkIter := range iteration {
				fillBufferWithMrExtend(
					buffer128,
					buffer256,
					sec.MemoryAddress+iter*PageSize+chunkIter*granularity,
					data,
					uint64(sec.DataOffset)+iter*PageSize+chunkIter*granularity,
				)
				hasher.Write(buffer128[:])
				hasher.Write(buffer256[:])
			}
		}
	}
}

// processSectionQemu processes a single metadata section
// Qemu does MEM_PAGE_ADD for all pages and then does MR.EXTEND for each page
func processSectionQemu(data []byte, sec *TdxMetadataSection, buffer128 *[MRTDExtensionBufferSize]byte,
	buffer256 *[TDHMRExtendGranularity]byte, hasher io.Writer) {
	nrPages := sec.MemoryDataSize / PageSize

	// Process memory pages
	for iter := range nrPages {
		if sec.Attributes&TDXMetadataAttributesExtendMemPageAdd == 0 {
			// Use TDCALL [TDH.MEM.PAGE.ADD]
			fillBufferWithMemPageAdd(buffer128, sec.MemoryAddress+iter*PageSize)
			hasher.Write(buffer128[:])
		}
	}

	// Process MR.EXTEND
	if sec.Attributes&TDXMetadataAttributesExtendMR != 0 {
		// Use TDCALL [TDH.MR.EXTEND]
		granularity := uint64(TDHMRExtendGranularity)
		iteration := uint64(sec.RawDataSize) / granularity
		for chunkIter := range iteration {
			fillBufferWithMrExtend(
				buffer128,
				buffer256,
				sec.MemoryAddress+chunkIter*granularity,
				data,
				uint64(sec.DataOffset)+chunkIter*granularity,
			)
			hasher.Write(buffer128[:])
			hasher.Write(buffer256[:])
		}
	}
}

// BuildMRTD builds the MRTD from a raw TDVF image file
func BuildMRTD(data []byte, qemuCompat bool) ([]byte, error) {
	metadataOffset := findMetadataOffset(data)

	descriptor, err := readMetadataDescriptor(data, metadataOffset)
	if err != nil {
		return nil, fmt.Errorf("invalid descriptor: %w", err)
	}

	return processSections(data, metadataOffset, descriptor, qemuCompat)
}
