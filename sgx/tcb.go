package sgx

import (
	"fmt"
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
	fmt.Printf("\n=== TCB Matching Algorithm (Intel PCS/ECDSA-P256-SHA256) ===\n")
	fmt.Printf("Quote Platform SVNs: %v\n", cpusvn[:])
	fmt.Printf("Quote PCESVN: %d\n", pcesvn)
	fmt.Printf("Total TCB Levels to evaluate: %d\n\n", len(tcb.TCBLevels))

	for levelIndex, level := range tcb.TCBLevels {
		fmt.Printf("Evaluating TCB level %d (status: %s)...\n", levelIndex, level.TCBStatus)

		matched := true
		for i := 0; i < 16; i++ {
			tcbSVN := level.TCB.SGXTCBComponents[i].SVN
			quoteSVN := int(cpusvn[i])
			fmt.Printf("  Component %d [%s]: quote SVN=%d, TCB SVN=%d", i, getSGXComponentName(i), quoteSVN, tcbSVN)
			if quoteSVN < tcbSVN {
				fmt.Printf(" FAIL (quote SVN too low)\n")
				matched = false
				break
			}
			fmt.Printf(" OK\n")
		}

		if matched {
			tcbPCESVN := level.TCB.PCESVN
			fmt.Printf("  PCESVN: quote=%d, TCB=%d", pcesvn, tcbPCESVN)
			if pcesvn < tcbPCESVN {
				fmt.Printf(" FAIL (quote PCESVN too low)\n")
				matched = false
			} else {
				fmt.Printf(" OK\n")
			}
		}

		if matched {
			fmt.Printf("Matched TCB level %d: %s\n", levelIndex, level.TCBStatus)
			if len(level.AdvisoryIDs) > 0 {
				fmt.Printf("  Advisory IDs: %v\n", level.AdvisoryIDs)
			}
			return level.TCBStatus, level.AdvisoryIDs
		}
	}

	fmt.Printf("No TCB level matched - platform may be revoked\n")
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
