// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package mrtd

import (
	"encoding/hex"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testdataHashDefault = "2d5e15c1c23282d5bc8642a817ed2025503bd9a06a49976cb9e1fdfc6352e659c9f854cf6a450575bf11f52387f3af23"
	testdataHashQemu    = "9d5ae0f1561a10bd825e2dceed5c29778147dd49a965a51c76e1d85cdf376cd6d044b6c874d65050f405a3dcf561a188"
)

func TestBuildMRTD(t *testing.T) {
	filePath := "testdata/OVMF.fd"
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Skipf("Skipping test: %v", err)
		return
	}

	hash, err := BuildMRTD(data, false)
	if err != nil {
		t.Fatalf("BuildMRTD failed: %v", err)
	}
	log.Printf("MRTD Hash: %x\n", hash)
	assert.Equal(t, testdataHashDefault, hex.EncodeToString(hash), "MRTD hashes do not match")

	hash, err = BuildMRTD(data, true)
	if err != nil {
		t.Fatalf("BuildMRTD failed: %v", err)
	}
	log.Printf("MRTD Hash Qemu compatible: %x\n", hash)
	assert.Equal(t, testdataHashQemu, hex.EncodeToString(hash), "MRTD hashes do not match")
}
