// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package sgx

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

type SignedTCBInfo struct {
	TCBInfo   json.RawMessage `json:"tcbInfo"`
	Signature string          `json:"signature"`
}

// TCB information from Intel PCS
type TCBInfo struct {
	ID         string     `json:"id"`
	Version    int        `json:"version"`
	IssueDate  string     `json:"issueDate"`
	NextUpdate string     `json:"nextUpdate"`
	FMSPC      string     `json:"fmspc"`
	PCEId      string     `json:"pceId"`
	TCBType    int        `json:"tcbType"`
	TCBLevels  []TCBLevel `json:"tcbLevels"`
	TcbEvalNum int        `json:"tcbEvaluationDataNumber"`
	// Present only in TDX TCB Info; empty for SGX.
	TDXModuleIdentities []TDXModuleIdentity `json:"tdxModuleIdentities"`
}

// TDXModuleIdentity describes one TDX module major version and the ISVSVNs
// Intel considers acceptable for it.
type TDXModuleIdentity struct {
	ID        string              `json:"id"`
	TCBLevels []TDXModuleTCBLevel `json:"tcbLevels"`
}

type TDXModuleTCBLevel struct {
	TCB         TDXModuleTCB `json:"tcb"`
	TCBDate     string       `json:"tcbDate"`
	TCBStatus   string       `json:"tcbStatus"`
	AdvisoryIDs []string     `json:"advisoryIDs"`
}

type TDXModuleTCB struct {
	ISVSVN int `json:"isvsvn"`
}

type TCBLevel struct {
	TCB         TCBComponents `json:"tcb"`
	TCBDate     string        `json:"tcbDate"`
	TCBStatus   string        `json:"tcbStatus"`
	AdvisoryIDs []string      `json:"advisoryIDs"`
}

type TCBComponents struct {
	SGXTCBComponents []TCBComponent `json:"sgxtcbcomponents"`
	PCESVN           int            `json:"pcesvn"`
	TDXTCBComponents []TCBComponent `json:"tdxtcbcomponents"`
}

type TCBComponent struct {
	SVN      int    `json:"svn"`
	Category string `json:"category,omitempty"`
	Type     string `json:"type,omitempty"`
}

// iterate through tcbInfo levels and return the status and advisory IDs of the first level whose SVN requirements are
// met by cpusvn/pcesvn.
func (tcb *TCBInfo) evaluateTCBLevel(cpusvn [16]byte, pcesvn int) (string, []string) {
	slog.Debug("TCB matching starting", "cpusvn", cpusvn[:], "pcesvn", pcesvn, "levels", len(tcb.TCBLevels))

	for levelIndex, level := range tcb.TCBLevels {
		slog.Debug("evaluating TCB level", "index", levelIndex, "status", level.TCBStatus)

		matched := true
		for i := 0; i < 16; i++ {
			tcbSVN := level.TCB.SGXTCBComponents[i].SVN
			quoteSVN := int(cpusvn[i])
			if quoteSVN < tcbSVN {
				slog.Debug("component SVN too low", "component", i, "name", getSGXComponentName(i), "quoteSVN", quoteSVN, "tcbSVN", tcbSVN)
				matched = false
				break
			}
			slog.Debug("component SVN OK", "component", i, "name", getSGXComponentName(i), "quoteSVN", quoteSVN, "tcbSVN", tcbSVN)
		}

		if matched {
			tcbPCESVN := level.TCB.PCESVN
			if pcesvn < tcbPCESVN {
				slog.Debug("PCESVN too low", "quotePCESVN", pcesvn, "tcbPCESVN", tcbPCESVN)
				matched = false
			} else {
				slog.Debug("PCESVN OK", "quotePCESVN", pcesvn, "tcbPCESVN", tcbPCESVN)
			}
		}

		if matched {
			slog.Debug("matched TCB level", "index", levelIndex, "status", level.TCBStatus, "advisoryIDs", level.AdvisoryIDs)
			return level.TCBStatus, level.AdvisoryIDs
		}
	}

	slog.Debug("no TCB level matched, platform may be revoked")
	return "Revoked", []string{}
}

func getSGXComponentName(index int) string {
	componentNames := []string{
		"BIOS (Early Microcode)",
		"OS/VMM (SGX Late Microcode)",
		"OS/VMM (TXT SINIT)",
		"BIOS",
		"BIOS",
		"BIOS",
		"Reserved",
		"OS/VMM (SEAMLDR ACM)",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
	}
	if index >= 0 && index < len(componentNames) {
		return componentNames[index]
	}
	return "Unknown"
}

// Collateral flavours Intel serves for the same FMSPC
const (
	UpdateStandard = "standard"
	UpdateEarly    = "early"
)

// Platform carries the SVNs a platform reports
type Platform struct {
	TCBComponents [16]int
	PCESVN        int
	TEETCBSVN     []byte
}

// MatchLevel walks tcbLevels newest-first and returns the first level whose SVN
// requirements the platform meets, or nil if it meets none.
func (tcb *TCBInfo) MatchLevel(p Platform) *TCBLevel {
	isTDX := tcb.ID == "TDX"
	for i := range tcb.TCBLevels {
		lvl := &tcb.TCBLevels[i]
		if !meetsSGX(lvl, p) {
			continue
		}
		if isTDX && p.TEETCBSVN != nil && !meetsTDX(lvl, p.TEETCBSVN) {
			continue
		}
		return lvl
	}
	return nil
}

func meetsSGX(lvl *TCBLevel, p Platform) bool {
	for i, c := range lvl.TCB.SGXTCBComponents {
		if i >= len(p.TCBComponents) {
			break
		}
		if c.SVN > p.TCBComponents[i] {
			return false
		}
	}
	return lvl.TCB.PCESVN <= p.PCESVN
}

func meetsTDX(lvl *TCBLevel, teeTCBSVN []byte) bool {
	start := 0
	if len(teeTCBSVN) > 1 && teeTCBSVN[1] >= 1 {
		start = 2
	}
	for i, c := range lvl.TCB.TDXTCBComponents {
		if i < start || i >= len(teeTCBSVN) {
			continue
		}
		if c.SVN > int(teeTCBSVN[i]) {
			return false
		}
	}
	return true
}

// MatchModule returns the tdxModuleIdentities entry for the platform's TDX
// module major version, and the newest level its ISVSVN satisfies.
func (tcb *TCBInfo) MatchModule(teeTCBSVN []byte) (string, *TDXModuleIdentity, *TDXModuleTCBLevel) {
	if len(teeTCBSVN) < 2 || teeTCBSVN[1] < 1 {
		return "", nil, nil
	}
	id := fmt.Sprintf("TDX_%02d", teeTCBSVN[1])
	for i := range tcb.TDXModuleIdentities {
		ident := &tcb.TDXModuleIdentities[i]
		if ident.ID != id {
			continue
		}
		for j := range ident.TCBLevels {
			if ident.TCBLevels[j].TCB.ISVSVN <= int(teeTCBSVN[0]) {
				return id, ident, &ident.TCBLevels[j]
			}
		}
		return id, ident, nil
	}
	return id, nil, nil
}
