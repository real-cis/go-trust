// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

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

// MRTDBuffers holds reusable buffers for MRTD computation.
type MRTDBuffers struct {
	Buf128 [MRTDExtensionBufferSize]byte // metadata buffer (page add and mr extend)
	Buf256 [TDHMRExtendGranularity]byte  // data buffer (mr extend)
}

// Reset clears both buffers, setting all bytes to zero.
func (b *MRTDBuffers) Reset() {
	clear(b.Buf128[:])
	clear(b.Buf256[:])
}

// MemPageAdd fills Buf128 with memory page add data.
func (b *MRTDBuffers) MemPageAdd(gpa uint64) {
	b.Reset()

	// Byte 0 through 11 contain the ASCII string 'MEM.PAGE.ADD'.
	// Byte 16 through 23 contain the GPA (in little-endian format).
	// All the other bytes contain 0.
	copy(b.Buf128[:MemPageAddASCIISize], []byte("MEM.PAGE.ADD"))
	binary.LittleEndian.PutUint64(b.Buf128[MemPageAddGPAOffset:MemPageAddGPAOffset+MemPageAddGPASize], gpa)
}

// MrExtend fills Buf128 and Buf256 for MR_EXTEND operation.
func (b *MRTDBuffers) MrExtend(gpa uint64, data []byte, dataOffset uint32) {
	b.Reset()

	// Byte 0 through 8 contain the ASCII string 'MR.EXTEND'.
	// Byte 16 through 23 contain the GPA (in little-endian format).
	copy(b.Buf128[:MRExtendASCIISize], []byte("MR.EXTEND"))
	binary.LittleEndian.PutUint64(b.Buf128[MRExtendGPAOffset:MRExtendGPAOffset+MRExtendGPASize], gpa)

	copy(b.Buf256[:], data[dataOffset:dataOffset+TDHMRExtendGranularity])
}
