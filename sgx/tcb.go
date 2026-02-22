package sgx

import (
	"log/slog"
)

type TCBInfoWrapper struct {
	TCBInfo   TCBInfo `json:"tcbInfo"`
	Signature string  `json:"signature"`
}

// TCB information from Intel PCS
type TCBInfo struct {
	Version    int        `json:"version"`
	IssueDate  string     `json:"issueDate"`
	NextUpdate string     `json:"nextUpdate"`
	FMSPC      string     `json:"fmspc"`
	PCEId      string     `json:"pceId"`
	TCBType    int        `json:"tcbType"`
	TCBLevels  []TCBLevel `json:"tcbLevels"`
	TcbEvalNum int        `json:"tcbEvaluationDataNumber"`
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

// evaluateTCBLevel iterates through tcbInfo levels (newest first) and returns
// the status and advisory IDs of the first level whose SVN requirements are all
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
