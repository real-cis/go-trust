package mrtd

import (
	"encoding/binary"
)

// Constants for buffer operations
const (
	MRTDExtensionBufferSize = 0x80
	TDHMRExtendGranularity  = 0x100
	MemPageAddASCIISize     = 0xc
	MemPageAddGPAOffset     = 0x10
	MemPageAddGPASize       = 0x8
	MRExtendASCIISize       = 0x9
	MRExtendGPAOffset       = 0x10
	MRExtendGPASize         = 0x8
)

// zeroize fills a byte array with zeros
func zeroize(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// fillBufferWithMemPageAdd fills a buffer with memory page add data
func fillBufferWithMemPageAdd(buf *[MRTDExtensionBufferSize]byte, gpa uint64) {
	zeroize(buf[:])

	// Byte 0 through 11 contain the ASCII string 'MEM.PAGE.ADD'.
	// Byte 16 through 23 contain the GPA (in little-endian format).
	// All the other bytes contain 0.
	copy(buf[:MemPageAddASCIISize], []byte("MEM.PAGE.ADD"))
	binary.LittleEndian.PutUint64(buf[MemPageAddGPAOffset:MemPageAddGPAOffset+MemPageAddGPASize], gpa)
}

// fillBufferWithMrExtend fills buffers for MR_EXTEND operation
func fillBufferWithMrExtend(
	buf128 *[MRTDExtensionBufferSize]byte,
	buf256 *[TDHMRExtendGranularity]byte,
	gpa uint64,
	data []byte,
	dataOffset uint64,
) {
	zeroize(buf128[:])
	zeroize(buf256[:])

	// Byte 0 through 8 contain the ASCII string 'MR.EXTEND'.
	// Byte 16 through 23 contain the GPA (in little-endian format).
	copy(buf128[:MRExtendASCIISize], []byte("MR.EXTEND"))
	binary.LittleEndian.PutUint64(buf128[MRExtendGPAOffset:MRExtendGPAOffset+MRExtendGPASize], gpa)

	copy(buf256[:], data[dataOffset:dataOffset+TDHMRExtendGranularity])
}
