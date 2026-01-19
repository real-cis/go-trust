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
)

var (
	OVMFTableFooterGUID      = guid.MustParse("96b582de-1fb2-45f7-baea-a366c55a082d")
	OVMFTableTDXMetadataGUID = guid.MustParse("e47a6535-984a-4798-865e-4685a7bf8ec2")
)

// FirmwareImage represents a TDVF/OVMF firmware binary image.
type FirmwareImage struct {
	Data []byte
}

// NewFirmwareImage creates a new FirmwareImage from raw bytes.
func NewFirmwareImage(data []byte) *FirmwareImage {
	return &FirmwareImage{Data: data}
}

// Size returns the size of the firmware image in bytes.
func (f *FirmwareImage) Size() int {
	return len(f.Data)
}

// locate the TDX metadata offset in the firmware image.
func (f *FirmwareImage) FindMetadataOffset() uint32 {
	imageSize := uint64(f.Size())
	// Check for OVMF table footer GUID
	footerGuidBuf := make([]byte, 16)
	copy(footerGuidBuf, f.Data[imageSize-OVMFTableFooterGUIDOffset:imageSize-OVMFTableFooterGUIDOffset+16])

	if bytes.Equal(guid.ToBytes(OVMFTableFooterGUID), footerGuidBuf) {
		return f.findMetadataOffsetFromOvmfTable()
	} else {
		// Try TDVF descriptor approach
		return f.findMetadataOffsetFromTdvfDescriptor()
	}
}

// finds metadata offset using OVMF table
func (f *FirmwareImage) findMetadataOffsetFromOvmfTable() uint32 {
	imageSize := uint64(f.Size())
	offset := imageSize - OVMFTableFooterGUIDOffset

	var tableLen uint16
	r := bytes.NewReader(f.Data[offset:])
	binary.Read(r, binary.LittleEndian, &tableLen)

	tableLen -= 16 + uint16(unsafe.Sizeof(uint16(0)))

	ovmfTableOffset := imageSize - OVMFTableFooterGUIDOffset - uint64(unsafe.Sizeof(uint16(0)))

	var count uint16 = 0
	for count < tableLen {
		guidBuf := f.Data[ovmfTableOffset-16 : ovmfTableOffset]

		var length uint16
		binary.LittleEndian.Uint16(f.Data[ovmfTableOffset-16-2:])
		length = binary.LittleEndian.Uint16(f.Data[ovmfTableOffset-16-2 : ovmfTableOffset-16])

		if bytes.Equal(guid.ToBytes(OVMFTableTDXMetadataGUID), guidBuf) {
			metadataOffsetOffset := ovmfTableOffset - 16 - 2 - 4
			offsetVal := binary.LittleEndian.Uint32(f.Data[metadataOffsetOffset : metadataOffsetOffset+4])
			return uint32(imageSize) - offsetVal - TdxMetadataGuidSize
		}
		ovmfTableOffset -= uint64(length)
		count += length
	}

	return 0 // If not found
}

// finds metadata offset using TDVF descriptor
func (f *FirmwareImage) findMetadataOffsetFromTdvfDescriptor() uint32 {
	imageSize := f.Size()
	offset := imageSize - TDVFDescriptorOffset

	val := binary.LittleEndian.Uint32(f.Data[offset : offset+4])
	return val - TdxMetadataGuidSize
}

// ReadMetadataDescriptor reads and returns the TDX metadata descriptor at the given offset.
func (f *FirmwareImage) ReadMetadataDescriptor(metadataOffset uint32) (*TdxMetadataDescriptor, error) {
	if metadataOffset >= uint32(f.Size()) {
		return nil, fmt.Errorf("offset out of bounds")
	}

	descOffset := metadataOffset + TdxMetadataGuidSize
	// metadataOffset points to GUID + Descriptor.
	// We want to skip GUID.

	if uint64(descOffset)+uint64(TdxMetadataDescriptorSize) > uint64(f.Size()) {
		return nil, fmt.Errorf("descriptor out of bounds")
	}

	descBytes := f.Data[descOffset : descOffset+uint32(TdxMetadataDescriptorSize)]
	var descriptor TdxMetadataDescriptor
	reader := bytes.NewReader(descBytes)
	binary.Read(reader, binary.LittleEndian, &descriptor)

	if !descriptor.IsValid() {
		return nil, fmt.Errorf("invalid descriptor")
	}

	return &descriptor, nil
}

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

// processes the metadata sections and builds the MRTD hash.
func (desc *TdxMetadataDescriptor) ProcessSections(image *FirmwareImage, metadataOffset uint32, qemuCompat bool) ([]byte, error) {
	// Metadata buffer starts after GUID
	start := metadataOffset + TdxMetadataGuidSize
	if uint64(start)+uint64(desc.Length) > uint64(image.Size()) {
		return nil, fmt.Errorf("metadata buffer out of bounds")
	}

	metadataBuf := image.Data[start : start+desc.Length]

	var buffers MRTDBuffers
	hasher := sha512.New384()

	// Process each section
	for i := range desc.NumberOfSectionEntry {
		secOffset := TdxMetadataDescriptorSize + i*TdxMetadataSectionSize

		var section TdxMetadataSection
		secReader := bytes.NewReader(metadataBuf[secOffset:])
		binary.Read(secReader, binary.LittleEndian, &section)

		if err := section.Validate(); err != nil {
			return nil, err
		}
		if qemuCompat {
			section.ProcessQemu(image, &buffers, hasher)
		} else {
			section.Process(image, &buffers, hasher)
		}
	}

	// Get final hash
	return hasher.Sum(nil), nil
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

// Validate validates a metadata section
func (sec *TdxMetadataSection) Validate() error {
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

// Process processes a single metadata section.
// Default spec is to MEM_PAGE_ADD followed by MR.EXTEND per page (4K)
func (sec *TdxMetadataSection) Process(image *FirmwareImage, buffers *MRTDBuffers, hasher io.Writer) {
	fmt.Printf("Processing section type: %d \n", sec.Type)

	nrPages := sec.MemoryDataSize / PageSize

	// Process memory pages
	for iter := range nrPages {
		if sec.Attributes&TDXMetadataAttributesExtendMemPageAdd == 0 {
			// Use TDCALL [TDH.MEM.PAGE.ADD]
			buffers.MemPageAdd(sec.MemoryAddress + iter*PageSize)
			hasher.Write(buffers.Buf128[:])
		}

		// Process MR.EXTEND
		if sec.Attributes&TDXMetadataAttributesExtendMR != 0 {
			// Use TDCALL [TDH.MR.EXTEND]
			granularity := uint64(TDHMRExtendGranularity)
			iteration := PageSize / granularity
			for chunkIter := range iteration {
				buffers.MrExtend(
					sec.MemoryAddress+iter*PageSize+chunkIter*granularity,
					image.Data,
					uint64(sec.DataOffset)+iter*PageSize+chunkIter*granularity,
				)
				hasher.Write(buffers.Buf128[:])
				hasher.Write(buffers.Buf256[:])
			}
		}
	}
}

// ProcessQemu processes a single metadata section using Qemu-compatible ordering.
// Qemu does MEM_PAGE_ADD for all pages and then does MR.EXTEND for each page
// https://github.com/intel-staging/qemu-tdx/issues/1
func (sec *TdxMetadataSection) ProcessQemu(image *FirmwareImage, buffers *MRTDBuffers, hasher io.Writer) {
	nrPages := sec.MemoryDataSize / PageSize

	// Process memory pages
	for iter := range nrPages {
		if sec.Attributes&TDXMetadataAttributesExtendMemPageAdd == 0 {
			// Use TDCALL [TDH.MEM.PAGE.ADD]
			buffers.MemPageAdd(sec.MemoryAddress + iter*PageSize)
			hasher.Write(buffers.Buf128[:])
		}
	}

	// Process MR.EXTEND
	if sec.Attributes&TDXMetadataAttributesExtendMR != 0 {
		// Use TDCALL [TDH.MR.EXTEND]
		granularity := uint64(TDHMRExtendGranularity)
		iteration := uint64(sec.RawDataSize) / granularity
		for chunkIter := range iteration {
			buffers.MrExtend(
				sec.MemoryAddress+chunkIter*granularity,
				image.Data,
				uint64(sec.DataOffset)+chunkIter*granularity,
			)
			hasher.Write(buffers.Buf128[:])
			hasher.Write(buffers.Buf256[:])
		}
	}
}

// BuildMRTD builds the MRTD from a raw TDVF image file
func BuildMRTD(data []byte, qemuCompat bool) ([]byte, error) {
	image := NewFirmwareImage(data)
	metadataOffset := image.FindMetadataOffset()
	descriptor, err := image.ReadMetadataDescriptor(metadataOffset)
	if err != nil {
		return nil, fmt.Errorf("invalid descriptor: %w", err)
	}

	return descriptor.ProcessSections(image, metadataOffset, qemuCompat)
}
