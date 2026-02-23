// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package ccel

import (
	"encoding/binary"
)

// parse raw bytes into structured data
type Buffer struct {
	ByteArray []byte
	Base      int
}

func NewBuffer(b []byte, base int) Buffer {
	return Buffer{
		ByteArray: b,
		Base:      base,
	}
}

func (b *Buffer) ParseUint8(start int) (uint8, int) {
	return b.ByteArray[start], start + 1
}

func (b *Buffer) ParseUint16(start int) (uint16, int) {
	val := binary.LittleEndian.Uint16(b.ByteArray[start : start+2])
	return val, start + 2
}

func (b *Buffer) ParseUint32(start int) (uint32, int) {
	val := binary.LittleEndian.Uint32(b.ByteArray[start : start+4])
	return val, start + 4
}

func (b *Buffer) ParseUint64(start int) (uint64, int) {
	val := binary.LittleEndian.Uint64(b.ByteArray[start : start+8])
	return val, start + 8
}

func (b *Buffer) ParseBytes(start, count int) ([]byte, int) {
	return b.ByteArray[start : start+count], start + count
}
