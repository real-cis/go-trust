package sgx

import "time"

// Parsed SGX/TDX DCAP quote
type Quote struct {
	Version    uint16
	SignType   uint16   // Attestation key type
	QESVN      uint16   // Quoting Enclave Security Version Number
	PCESVN     uint16   // Provisioning Certification Enclave Security Version Number
	QEVendorID [16]byte // QE Vendor ID from header
	UserData   [20]byte // User Data from header
	ReportBody ReportBody
	Signature  []byte
	AuthData   AuthenticationData
	QuoteType  QuoteType // SGX or TDX
}

// QuoteType indicates whether this is an SGX or TDX quote
type QuoteType int

const (
	QuoteSGX QuoteType = iota
	QuoteTDX
)

// ReportBody contains the SGX/TDX report body
type ReportBody struct {
	CPUSVN     [16]byte
	MiscSelect uint32
	Reserved1  [28]byte
	Attributes [16]byte
	MRENCLAVE  [32]byte // MRTD for TDX
	Reserved2  [32]byte
	MRSIGNER   [32]byte // MRCONFIGID for TDX
	Reserved3  [96]byte
	ISVProdID  uint16
	ISVSVN     uint16
	Reserved4  [60]byte
	ReportData [64]byte
}

// quote authentication data
type AuthenticationData struct {
	AttestationKey    []byte // ECDSA P-256 public key (64 bytes)
	CertificationData []byte
	QEReportSignature []byte
	QEReport          []byte
	QEAuthData        []byte
}

// quote verification result
type VerificationResult struct {
	Status      string
	TCBLevel    string   // UpToDate, OutOfDate, ConfigurationNeeded, etc.
	AdvisoryIDs []string // List of security advisory IDs
	Timestamp   time.Time
	QuoteType   QuoteType // SGX or TDX
}

type Verifier interface {
	Verify(quote *Quote) (*VerificationResult, error)
}
