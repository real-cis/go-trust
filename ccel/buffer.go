package ccel

import (
	"encoding/binary"
	"fmt"
	"log"
	"unicode"
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

func (b *Buffer) Dump() {
	l := log.Default()
	index := 0
	length := len(b.ByteArray)
	baseAddr := ""
	hexStr := ""
	readableStr := ""
	for ; index < length; index++ {
		if index%16 == 0 {
			if len(baseAddr) != 0 {
				l.Println(baseAddr, hexStr, readableStr)
			}
			baseAddr = fmt.Sprintf("%08x", b.Base+index/16*16)
			hexStr = ""
			readableStr = ""
		}
		chr := b.ByteArray[index]
		hexStr += fmt.Sprintf("%02x ", chr)
		switch chr {
		case 0xC, 0xB, 0xA, 0xD, 0x9:
			readableStr += "."
		default:

			if !unicode.IsPrint(rune(chr)) {
				readableStr += "."
			} else {
				readableStr += string(chr)
			}
		}
	}
	if index%16 != 0 {
		for i := 0; i < 16-index%16; i++ {
			hexStr += "   "
		}
		l.Println(baseAddr, hexStr, readableStr)
	} else if index == length {
		l.Println(baseAddr, hexStr, readableStr)
	}
}
