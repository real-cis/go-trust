// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package ccel

import (
	"encoding/hex"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.com/real-cis/cc/go-trust/pkg/tcg"
	"gitlab.com/real-cis/cc/go-trust/pkg/uefi"
)

const (
	expectedRTMR0     = "c91349a31550775fa2ff0e3a357949320aa12680ce289bdf0c6966b3c803ffeac6344bb8a1dfd60fbf5a07da1ca824c5"
	EFISecureBootHash = "2cded0c6f453d4c6f59c5e14ec61abc6b018314540a2367cba326a52aa2b315ccc08ce68a816ce09c6ef2ac7e514ae1f"
	EFIPKHash         = "1e71413273207ab39c817a24f5f97f1e8ee63b1086c602c675a348da63b06855f75a3916e92647c84c0c92b2513c400c"
	EFIKEKHash        = "ade13d7b6cbd3bee3c6571c9d090550b83ecb8435c11bc6565f42ce0f799124a75e26a33c37419c8c1fd36507193627b"
	EFIDbHash         = "125e0a524c332f19251973dab2eec2a36bf35f1b6ce585bf57c0c956cae5424dc05d8a087b48b2bc5b563acb63c360a8"
	EFIDbxHash        = "5f95c5051ade2e2314961e4011150fbe3315c0b78c93b27be3ac8e4df73930e6ad82aa50ac3591d292ce364b04c850c7"
	CFVHash           = "cc7dbc6e48cd02d110c75a560eb35b6fba8e1665576fe2103dc1c78a9acc73fe386c2b1778c980e91e51f0af9e25569b"
)

func TestEventLog(t *testing.T) {
	elBin, err := os.ReadFile("testdata/CCEL.1")
	assert.Nil(t, err)

	el := NewEventLogger(elBin, nil, tcg.PCClientFormat)
	e := el.Parse()
	assert.Nil(t, e)

	summary := el.Summary()

	for _, ev := range summary.Events {
		efiVar := ""
		if ev.EFIVariable != nil {
			efiVar = *ev.EFIVariable
		}
		log.Printf("RTMR: %d, Event Type: %v, EFI Variable: %q, Digest: %s\n",
			ev.RTMRIndex, ev.EventType, efiVar, hex.EncodeToString(ev.Digest))

		// Secureboot variable digests below are the DRIVER_CONFIG measurements
		if ev.EFIVariable == nil || ev.EventType != tcg.EvEfiVariableDriverConfig.String() {
			continue
		}
		switch *ev.EFIVariable {
		case "PK":
			assert.Equal(t, EFIPKHash, hex.EncodeToString(ev.Digest))
		case "KEK":
			assert.Equal(t, EFIKEKHash, hex.EncodeToString(ev.Digest))
		case "db":
			assert.Equal(t, EFIDbHash, hex.EncodeToString(ev.Digest))
		case "dbx":
			assert.Equal(t, EFIDbxHash, hex.EncodeToString(ev.Digest))
		case "SecureBoot":
			assert.Equal(t, EFISecureBootHash, hex.EncodeToString(ev.Digest))
		}
	}

	for index, val := range summary.RTMRs {
		log.Printf("RTMR[%d]: %s\n", index, hex.EncodeToString(val))
	}

	assert.Equal(t, expectedRTMR0, hex.EncodeToString(summary.RTMRs[0]))
}

func TestFilterByEventType(t *testing.T) {
	elBin, err := os.ReadFile("testdata/CCEL.1")
	assert.Nil(t, err)

	el := NewEventLogger(elBin, nil, tcg.PCClientFormat)
	e := el.Parse()
	assert.Nil(t, e)

	filteredEvents := el.FilterByEventType([]tcg.EventType{
		tcg.EvEfiPlatformFirmwareBlob2,
		tcg.EvEfiVariableDriverConfig,
	})

	for _, fel := range filteredEvents {
		eventType := fel.GetEventType()
		assert.Contains(t, []tcg.EventType{tcg.EvEfiPlatformFirmwareBlob2, tcg.EvEfiVariableDriverConfig}, eventType)

		switch eventType {
		case tcg.EvEfiPlatformFirmwareBlob2:
			assert.Equal(t, CFVHash, hex.EncodeToString(fel.GetDigests()[0].Hash))
		case tcg.EvEfiVariableDriverConfig:
			uefiVar, err := uefi.NewUefiVariableDataFromBytes(fel.GetEvent())
			assert.NoError(t, err)

			switch uefiVar.Name.String() {
			case "PK":
				assert.Equal(t, EFIPKHash, hex.EncodeToString(fel.GetDigests()[0].Hash))
			case "KEK":
				assert.Equal(t, EFIKEKHash, hex.EncodeToString(fel.GetDigests()[0].Hash))
			case "db":
				assert.Equal(t, EFIDbHash, hex.EncodeToString(fel.GetDigests()[0].Hash))
			case "dbx":
				assert.Equal(t, EFIDbxHash, hex.EncodeToString(fel.GetDigests()[0].Hash))
			case "SecureBoot":
				assert.Equal(t, EFISecureBootHash, hex.EncodeToString(fel.GetDigests()[0].Hash))
			}
		}
	}
}
