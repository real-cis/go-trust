package sgx

import (
	"fmt"
	"sync"
	"time"

	"crypto/x509"
)

// Quote holds the raw decoded fields of a DCAP SGX/TDX quote.
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

// QuoteType indicates whether this is an SGX or TDX quote.
type QuoteType int

const (
	QuoteSGX QuoteType = iota
	QuoteTDX
)

// ReportBody contains the SGX/TDX report body.
type ReportBody struct {
	CPUSVN     [16]byte
	MiscSelect uint32
	Reserved1  [28]byte
	Attributes [16]byte
	MrEnclave  [32]byte // MRTD for TDX
	Reserved2  [32]byte
	MrSigner   [32]byte // MRCONFIGID for TDX
	Reserved3  [96]byte
	ISVProdID  uint16
	ISVSVN     uint16
	Reserved4  [60]byte
	ReportData [64]byte
}

type AuthenticationData struct {
	AttestationKey    []byte // ECDSA P-256 public key (64 bytes)
	CertificationData []byte
	QEReportSignature []byte
	QEReport          []byte
	QEAuthData        []byte
}

// ParsedQuote wraps a raw Quote and lazily caches derived values such as the
// parsed certificate chain and FMSPC.
type ParsedQuote struct {
	*Quote

	certChainOnce sync.Once
	certChainVal  []*x509.Certificate
	certChainErr  error

	fmspcOnce sync.Once
	fmspcVal  string
	fmspcErr  error
}

func (q *ParsedQuote) IsSGX() bool { return q.QuoteType == QuoteSGX }

func (q *ParsedQuote) IsTDX() bool { return q.QuoteType == QuoteTDX }

func (q *ParsedQuote) QuoteTypeString() string {
	switch q.QuoteType {
	case QuoteSGX:
		return "SGX"
	case QuoteTDX:
		return "TDX"
	default:
		return "Unknown"
	}
}

type VerificationResult struct {
	TCBLevel    string   // UpToDate, OutOfDate, ConfigurationNeeded, etc.
	AdvisoryIDs []string // List of security advisory IDs
	Timestamp   time.Time
	QuoteType   QuoteType
}

type QuoteVerifier struct {
	Quote  *ParsedQuote
	Client Client
}

// Verify performs end-to-end verification of the quote against the TCB service:
//  1. extracts the FMSPC from the embedded PCK certificate,
//  2. fetches the current TCB info from the service,
//  3. verifies the PCK certificate chain against the Intel SGX Root CA,
//  4. verifies the quote's ECDSA signature, and
//  5. Verify QE Report data binding.
//  6. evaluates the platform's TCB level.
func (v *QuoteVerifier) Verify() (*VerificationResult, error) {
	q := v.Quote
	client := v.Client

	if len(q.AuthData.CertificationData) == 0 {
		return nil, fmt.Errorf("no certification data in quote - quote may be malformed or use local attestation format")
	}

	// 1. Extract platform identity.
	fmspc, err := q.FMSPC()
	if err != nil {
		return nil, fmt.Errorf("failed to extract FMSPC: %w", err)
	}
	fmt.Printf("Extracted FMSPC: %s\n", fmspc)

	// 2. Fetch TCB info from the service.
	var tcbInfo *TCBInfo
	if q.IsTDX() {
		fmt.Printf("Fetching TDX TCB info...\n")
		tcbInfo, err = client.GetTDXTCBInfo(fmspc)
	} else {
		fmt.Printf("Fetching SGX TCB info...\n")
		tcbInfo, err = client.GetTCBInfo(fmspc)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get TCB info: %w", err)
	}
	fmt.Printf("TCB info retrieved: issueDate=%s levels=%d\n", tcbInfo.IssueDate, len(tcbInfo.TCBLevels))

	// 3. Extract and verify certificate chain.
	chain, err := q.CertChain()
	if err != nil {
		return nil, fmt.Errorf("failed to extract certificate chain: %w", err)
	}

	fmt.Printf("Fetching CRLs for revocation checking...\n")
	rootCRL, err := client.GetRootCACRL()
	if err != nil {
		fmt.Printf("Warning: failed to get root CA CRL: %v\n", err)
	}
	pckCRL, err := client.GetPCKCRL("processor")
	if err != nil {
		fmt.Printf("Warning: failed to get PCK CRL: %v\n", err)
	}

	fmt.Printf("Verifying certificate chain...\n")
	if err := verifyCertChain(chain[0], chain[1:], rootCRL, pckCRL); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// 4. Verify quote signature.
	fmt.Printf("Verifying quote signature...\n")
	if err := q.VerifySignature(); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// 5. Verify QE Report data binding.
	fmt.Printf("Verifying QE report data binding...\n")
	if err := q.VerifyQEReportData(); err != nil {
		return nil, fmt.Errorf("QE report data verification failed: %w", err)
	}

	// 6. Evaluate TCB level.
	fmt.Printf("Evaluating TCB level...\n")
	status, advisories := tcbInfo.evaluateTCBLevel(q.ReportBody.CPUSVN, int(q.PCESVN))

	return &VerificationResult{
		TCBLevel:    status,
		AdvisoryIDs: advisories,
		Timestamp:   time.Now(),
		QuoteType:   q.QuoteType,
	}, nil
}
