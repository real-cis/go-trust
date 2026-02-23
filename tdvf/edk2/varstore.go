// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package edk2

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"log"

	"gitlab.com/real-cis/cc/go-trust/pkg/uefi"
)

const (
	// Firmware volume signature
	FVH_SIGNATURE = 0x4856465f // "_FVH"

	// Variable header magic
	VAR_HEADER_MAGIC = 0x55aa

	// Variable state - valid
	VAR_STATE_VALID = 0x3f

	// Variable store format
	VARSTORE_FORMAT = 0x5a

	// Variable store state
	VARSTORE_STATE = 0xfe
)

// Edk2VarStore represents an EDK2 variable store
type Edk2VarStore struct {
	filedata  []byte
	start     int
	end       int
	cfvOffset int
	cfvLength uint64
	cfvParsed bool
}

// computes SHA384 hash of the Configuration Firmware Volume
func (s *Edk2VarStore) MeasureCFV() []byte {
	if !s.cfvParsed || s.cfvLength == 0 {
		return nil
	}

	cfvEnd := s.cfvOffset + int(s.cfvLength)
	if cfvEnd > len(s.filedata) {
		cfvEnd = len(s.filedata)
	}

	cfvData := s.filedata[s.cfvOffset:cfvEnd]

	hash := sha512.Sum384(cfvData)
	return hash[:]
}

func NewEdk2VarStore(data []byte) (*Edk2VarStore, error) {
	store := &Edk2VarStore{
		filedata: data,
	}

	if err := store.parseVolume(); err != nil {
		return nil, err
	}

	return store, nil
}

// FindNvData searches for the NvData GUID in the data
func FindNvData(data []byte) int {
	offset := 0
	for offset+64 < len(data) {
		guid, err := ParseGUIDBin(data, offset+16)
		if err == nil && guid == GUIDNvData {
			return offset
		}
		if err == nil && guid == GUIDFfs {
			if offset+40 <= len(data) {
				tlen := binary.LittleEndian.Uint32(data[offset+32 : offset+36])
				offset += int(tlen)
				continue
			}
		}
		offset += 1024
	}
	return -1
}

// FirmwareVolumeHeader represents the firmware volume header structure
type FirmwareVolumeHeader struct {
	Vlen    uint64
	Sig     uint32
	Attr    uint32
	Hlen    uint16
	Csum    uint16
	Xoff    uint16
	_       uint8 // padding
	Rev     uint8
	Blocks  uint32
	Blksize uint32
}

// VarStoreHeader represents the variable store header structure
type VarStoreHeader struct {
	Size     uint32
	Format   uint8
	State    uint8
	Reserved [6]byte
}

// VariableHeader represents a single variable entry header
type VariableHeader struct {
	Magic    uint16
	State    uint8
	Reserved uint8
	Attr     uint32
	Count    uint64
	// Timestamp is 16 bytes at offset 16 (parsed separately)
	// PkIdx, NameSize, DataSize are at offset 32 (parsed separately)
}

func (s *Edk2VarStore) parseVolume() error {
	offset := FindNvData(s.filedata)
	if offset == -1 {
		return fmt.Errorf("varstore not found")
	}

	guid, err := ParseGUIDBin(s.filedata, offset+16)
	if err != nil {
		return fmt.Errorf("failed to parse GUID: %w", err)
	}

	if offset+48 > len(s.filedata) {
		return fmt.Errorf("insufficient data for volume header")
	}

	var header FirmwareVolumeHeader
	err = binary.Read(bytes.NewReader(s.filedata[offset+32:]), binary.LittleEndian, &header)
	if err != nil {
		return fmt.Errorf("failed to parse firmware volume header: %w", err)
	}

	log.Printf("vol=%s vlen=0x%x rev=%d blocks=%d*%d (0x%x)",
		GUIDName(guid), header.Vlen, header.Rev, header.Blocks, header.Blksize, header.Blocks*header.Blksize)

	if header.Sig != FVH_SIGNATURE {
		return fmt.Errorf("not a firmware volume (signature mismatch)")
	}

	if guid != GUIDNvData {
		return fmt.Errorf("not a variable store (GUID mismatch)")
	}

	// Store CFV offset and length for measurement
	s.cfvOffset = offset
	s.cfvLength = header.Vlen
	s.cfvParsed = true

	return s.parseVarStore(offset + int(header.Hlen))
}

// parseVarStore parses the variable store header
func (s *Edk2VarStore) parseVarStore(start int) error {
	if start+28 > len(s.filedata) {
		return fmt.Errorf("insufficient data for varstore header")
	}

	guid, err := ParseGUIDBin(s.filedata, start)
	if err != nil {
		return fmt.Errorf("failed to parse varstore GUID: %w", err)
	}

	var header VarStoreHeader
	err = binary.Read(bytes.NewReader(s.filedata[start+16:]), binary.LittleEndian, &header)
	if err != nil {
		return fmt.Errorf("failed to parse varstore header: %w", err)
	}

	log.Printf("varstore=%s size=0x%x format=0x%x state=0x%x",
		GUIDName(guid), header.Size, header.Format, header.State)

	if guid != GUIDAuthVars {
		return fmt.Errorf("unknown varstore guid")
	}

	if header.Format != VARSTORE_FORMAT {
		return fmt.Errorf("unknown varstore format")
	}

	if header.State != VARSTORE_STATE {
		return fmt.Errorf("unknown varstore state")
	}

	s.start = start + 16 + 12
	s.end = start + int(header.Size)
	log.Printf("var store range: 0x%x -> 0x%x", s.start, s.end)

	return nil
}

// GetVarList retrieves all variables from the store
func (s *Edk2VarStore) GetVarList() (uefi.EfiVarList, error) {
	pos := s.start
	varlist := make(uefi.EfiVarList)

	for pos < s.end {
		// Check if we have enough data for the header
		if pos+44 > len(s.filedata) {
			break
		}

		// Read variable header using struct
		var varHeader VariableHeader
		err := binary.Read(bytes.NewReader(s.filedata[pos:]), binary.LittleEndian, &varHeader)
		if err != nil {
			break
		}

		if varHeader.Magic != VAR_HEADER_MAGIC {
			break
		}

		// Read additional fields at offset 32 (after 16-byte timestamp)
		pk := binary.LittleEndian.Uint32(s.filedata[pos+32 : pos+36])
		nsize := binary.LittleEndian.Uint32(s.filedata[pos+36 : pos+40])
		dsize := binary.LittleEndian.Uint32(s.filedata[pos+40 : pos+44])

		// Check if we have enough data for GUID, name and data
		dataEnd := pos + 44 + 16 + int(nsize) + int(dsize)
		if dataEnd > len(s.filedata) {
			break
		}

		if varHeader.State == VAR_STATE_VALID {
			// Parse GUID
			guid, err := ParseGUIDBin(s.filedata, pos+44)
			if err != nil {
				log.Printf("Failed to parse GUID at position 0x%x: %v", pos, err)
				break
			}

			name := uefi.NewUTF16(s.filedata, pos+44+16)

			// Extract variable data
			dataStart := pos + 44 + 16 + int(nsize)
			data := make([]byte, dsize)
			copy(data, s.filedata[dataStart:dataStart+int(dsize)])

			evar := uefi.NewEfiVar(name, guid, varHeader.Attr, data, varHeader.Count, pk)
			evar.ParseTime(s.filedata, pos+16)

			varlist[name.String()] = evar
		}

		// Move to next variable (aligned to 4 bytes)
		pos = pos + 44 + 16 + int(nsize) + int(dsize)
		pos = (pos + 3) & ^3 // align to 4 bytes
	}

	return varlist, nil
}
