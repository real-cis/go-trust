package tcb

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
