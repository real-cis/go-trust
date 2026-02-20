package sgx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"gitlab.com/real-cis/cc/go-trust/sgx/tcb"
)

var (
	// SGX Extension OID: 1.2.840.113741.1.13.1
	// FMSPC OID: 1.2.840.113741.1.13.1.4
	sgxExtensionOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	fmspcOID        = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
)

type PCSClient struct {
	*BaseClient
}

func NewPCSClient(baseURL string, apiKey string) *PCSClient {
	baseConfig := Config{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Timeout: 10 * time.Second,
	}

	return &PCSClient{
		BaseClient: NewBaseClient(baseConfig),
	}
}

func (v *PCSClient) Verify(quote *Quote) (*VerificationResult, error) {

	if len(quote.AuthData.CertificationData) == 0 {
		return nil, fmt.Errorf("no certification data in quote - quote may be malformed or use local attestation format")
	}

	fmt.Printf("Certification data present: %d bytes\n", len(quote.AuthData.CertificationData))

	// Extract FMSPC from quote cert extensions
	fmspc, err := extractFMSPC(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to extract FMSPC: %w", err)
	}

	fmt.Printf("Extracted FMSPC: %s\n", fmspc)

	var tcbInfo *tcb.TCBInfo

	if quote.QuoteType == QuoteTDX {
		fmt.Printf("Fetching TDX TCB info...\n")
		tcbInfo, err = v.GetTDXTCBInfo(fmspc)
	} else {
		fmt.Printf("Fetching SGX TCB info...\n")
		tcbInfo, err = v.GetTCBInfo(fmspc)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get TCB info: %w", err)
	}
	fmt.Printf("TCB Info %+v\n", tcbInfo)

	fmt.Printf("TCB info retrieved successfully\n")
	fmt.Printf("  Issue Date: %s\n", tcbInfo.IssueDate)
	fmt.Printf("  Next Update: %s\n", tcbInfo.NextUpdate)
	fmt.Printf("  TCB Evaluation Number: %d\n", tcbInfo.TcbEvalNum)
	fmt.Printf("  Number of TCB Levels: %d\n", len(tcbInfo.TCBLevels))

	// Extract PCK certificate from quote
	pckCert, err := extractPCKCertFromQuote(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to extract PCK certificate: %w", err)
	}

	fmt.Printf("PCK certificate extracted\n")

	// Get CRLs for revocation checking
	fmt.Printf("Fetching CRLs for revocation checking...\n")
	rootCRL, err := v.GetRootCACRL()
	if err != nil {
		fmt.Printf("Warning: failed to get root CA CRL: %v\n", err)
	}

	pckCRL, err := v.GetPCKCRL("processor")
	if err != nil {
		fmt.Printf("Warning: failed to get PCK CRL: %v\n", err)
	}

	// Verify certificate chain: PCK cert -> Intermediate CA -> Root CA
	fmt.Printf("Verifying certificate chain...\n")
	if err := verifyCertChain(quote, pckCert, rootCRL, pckCRL); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// Verify quote signature
	fmt.Printf("Verifying quote signature...\n")
	if err := verifyQuoteSignature(quote, pckCert); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Evaluate TCB level
	fmt.Printf("Evaluating TCB level...\n")
	tcbLevel, advisories := evaluateTCBLevel(quote, tcbInfo)

	result := &VerificationResult{
		Status:      tcbLevel,
		TCBLevel:    tcbLevel,
		AdvisoryIDs: advisories,
		Timestamp:   time.Now(),
		QuoteType:   quote.QuoteType,
	}

	return result, nil
}

// Helpers

func extractFMSPC(quote *Quote) (string, error) {
	// FMSPC is in the PCK certificate's SGX extensions
	pckCert, err := extractPCKCertFromQuote(quote)
	if err != nil {
		return "", err
	}

	for _, ext := range pckCert.Extensions {
		if !ext.Id.Equal(sgxExtensionOID) {
			continue
		}

		// Parse SGX extension - contains a SEQUENCE of extensions
		var sgxExts []struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.Unmarshal(ext.Value, &sgxExts); err != nil {
			return "", fmt.Errorf("failed to parse SGX extensions: %w", err)
		}

		for _, sgxExt := range sgxExts {
			if sgxExt.OID.Equal(fmspcOID) {
				if len(sgxExt.Value.Bytes) != 6 {
					return "", fmt.Errorf("invalid FMSPC length: %d (expected 6)", len(sgxExt.Value.Bytes))
				}
				return fmt.Sprintf("%X", sgxExt.Value.Bytes), nil
			}
		}
	}

	return "", fmt.Errorf("FMSPC not found in PCK certificate")
}

func extractPCKCertFromQuote(quote *Quote) (*x509.Certificate, error) {
	certs, err := extractCertChainFromQuote(quote)
	if err != nil {
		return nil, err
	}
	// First certificate is the PCK cert
	return certs[0], nil
}

func extractCertChainFromQuote(quote *Quote) ([]*x509.Certificate, error) {
	if len(quote.AuthData.CertificationData) == 0 {
		return nil, fmt.Errorf("no certification data in quote")
	}

	certData := quote.AuthData.CertificationData

	var certs []*x509.Certificate
	remaining := certData
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PEM certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		remaining = rest
	}

	if len(certs) > 0 {
		return certs, nil
	}

	cert, err := x509.ParseCertificate(certData)
	if err == nil {
		return []*x509.Certificate{cert}, nil
	}

	certs, err = x509.ParseCertificates(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate data: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in certification data")
	}

	return certs, nil
}

func verifyCertChain(quote *Quote, pckCert *x509.Certificate, rootCRL, pckCRL []byte) error {
	if pckCert == nil {
		return fmt.Errorf("PCK certificate is nil")
	}

	// Basic time validity check
	now := time.Now()
	if now.Before(pckCert.NotBefore) || now.After(pckCert.NotAfter) {
		return fmt.Errorf("PCK certificate is not valid at current time")
	}

	fmt.Printf("PCK certificate is valid (expires: %s)\n", pckCert.NotAfter.Format(time.RFC3339))

	// Build Intel Root CA trust pool
	rootPool := x509.NewCertPool()
	rootPool.AddCert(intelSGXRootCA())

	// Build intermediate cert pool from quote certification data
	intermediatePool := x509.NewCertPool()

	// Extract all certs from quote - first is PCK, rest are intermediates
	certs, err := extractCertChainFromQuote(quote)
	if err == nil && len(certs) > 1 {
		for i := 1; i < len(certs); i++ {
			intermediatePool.AddCert(certs[i])
			fmt.Printf("Added intermediate CA: %s\n", certs[i].Subject.CommonName)
		}
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := pckCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	fmt.Printf("Certificate chain verified (chain length: %d)\n", len(chains[0]))

	// TODO: Check CRLs for revocation

	return nil
}

// This is the well-known public root certificate used by Intel PCS
// Intel SGX Root CA certificate (valid until 2049)
func intelSGXRootCA() *x509.Certificate {
	pemData := `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		panic("failed to decode Intel Root CA PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("failed to parse Intel Root CA: %v", err))
	}

	return cert
}

func verifyQuoteSignature(quote *Quote, pckCert *x509.Certificate) error {
	// The quote signature is verified using the Attestation Key (ephemeral key)
	// stored in the signature data,
	// The PCK certificate is used to verify the QE Report signature.

	if len(quote.AuthData.AttestationKey) != 64 {
		return fmt.Errorf("invalid attestation key length: %d (expected 64)", len(quote.AuthData.AttestationKey))
	}

	pubKey, err := rawBytesToECDSAPublicKey(quote.AuthData.AttestationKey)
	if err != nil {
		return fmt.Errorf("failed to parse attestation key: %w", err)
	}

	signedData := make([]byte, 0, 432)

	signedData = append(signedData, serializeQuoteHeader(quote)...)
	signedData = append(signedData, serializeReportBody(&quote.ReportBody)...)

	fmt.Printf("Signed data length: %d bytes (header: 48, body: 384)\n", len(signedData))

	dataHash := sha256.Sum256(signedData)
	fmt.Printf("Data hash: %x\n", dataHash[:8])

	// ECDSA signature is in raw format: R (32 bytes) || S (32 bytes)
	if len(quote.Signature) < 64 {
		return fmt.Errorf("signature data too short: %d bytes (expected 64)", len(quote.Signature))
	}

	sig := struct {
		R, S *big.Int
	}{
		R: new(big.Int).SetBytes(quote.Signature[:32]),
		S: new(big.Int).SetBytes(quote.Signature[32:64]),
	}

	if !ecdsa.Verify(pubKey, dataHash[:], sig.R, sig.S) {
		return fmt.Errorf("ECDSA signature verification failed - signature does not match data hash")
	}
	fmt.Printf(" ECDSA signature verified successfully using Attestation Key\n")

	// TODO: Verify that QE Report's ReportData contains hash of attestation key
	// This binds the attestation key to the QE Report for the trust chain

	return nil
}

func rawBytesToECDSAPublicKey(rawKey []byte) (*ecdsa.PublicKey, error) {
	if len(rawKey) != 64 {
		return nil, fmt.Errorf("invalid key length: %d (expected 64)", len(rawKey))
	}

	// Extract X and Y coordinates
	x := new(big.Int).SetBytes(rawKey[:32])
	y := new(big.Int).SetBytes(rawKey[32:64])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return pubKey, nil
}

func serializeQuoteHeader(quote *Quote) []byte {
	result := make([]byte, 0, 48)

	result = append(result, byte(quote.Version), byte(quote.Version>>8))
	result = append(result, byte(quote.SignType), byte(quote.SignType>>8))

	// Reserved field 4 bytes - TEE Type is encoded here
	// For SGX: 0x00000000, For TDX: 0x00000081
	teeType := uint32(0)
	if quote.QuoteType == QuoteTDX {
		teeType = 0x81
	}
	result = append(result, byte(teeType), byte(teeType>>8),
		byte(teeType>>16), byte(teeType>>24))

	// QE SVN = 2 bytes
	result = append(result, byte(quote.QESVN), byte(quote.QESVN>>8))

	// PCE SVN = 2 bytes
	result = append(result, byte(quote.PCESVN), byte(quote.PCESVN>>8))

	// QE Vendor ID = 16 bytes
	result = append(result, quote.QEVendorID[:]...)

	// User Data = 20 bytes
	result = append(result, quote.UserData[:]...)

	if len(result) != 48 {
		panic(fmt.Sprintf("serialized quote header has wrong length: %d (expected 48)", len(result)))
	}

	return result
}

func serializeReportBody(body *ReportBody) []byte {
	result := make([]byte, 0, 384)
	result = append(result, body.CPUSVN[:]...)
	result = append(result, byte(body.MiscSelect), byte(body.MiscSelect>>8),
		byte(body.MiscSelect>>16), byte(body.MiscSelect>>24))
	result = append(result, body.Reserved1[:]...)
	result = append(result, body.Attributes[:]...)
	result = append(result, body.MRENCLAVE[:]...)
	result = append(result, body.Reserved2[:]...)
	result = append(result, body.MRSIGNER[:]...)
	result = append(result, body.Reserved3[:]...)
	result = append(result, byte(body.ISVProdID), byte(body.ISVProdID>>8))
	result = append(result, byte(body.ISVSVN), byte(body.ISVSVN>>8))
	result = append(result, body.Reserved4[:]...)
	result = append(result, body.ReportData[:]...)
	return result
}

// name/description for each SGX TCB component
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

func evaluateTCBLevel(quote *Quote, tcbInfo *tcb.TCBInfo) (string, []string) {
	quoteCPUSVN := quote.ReportBody.CPUSVN

	quotePCESVN := int(quote.PCESVN)

	fmt.Printf("\n=== TCB Matching Algorithm (Intel PCS/ECDSA-P256-SHA256) ===\n")
	fmt.Printf("Quote Platform SVNs: %v\n", quoteCPUSVN[:])
	fmt.Printf("Quote PCESVN: %d\n", quotePCESVN)
	fmt.Printf("Total TCB Levels to evaluate: %d\n\n", len(tcbInfo.TCBLevels))

	// Iterate through TCB levels from newest (most secure) to oldest
	for levelIndex, level := range tcbInfo.TCBLevels {
		fmt.Printf("Evaluating TCB level %d (status: %s)...\n", levelIndex, level.TCBStatus)

		allComponentsMatch := true

		// Check all 16 SGX TCB components
		for i := 0; i < 16; i++ {
			tcbSVN := level.TCB.SGXTCBComponents[i].SVN
			quoteSVN := int(quoteCPUSVN[i])
			compName := getSGXComponentName(i)

			fmt.Printf("  Component %d [%s]: quote SVN=%d, TCB SVN=%d", i, compName, quoteSVN, tcbSVN)

			// Quote's SVN must be >= TCB level's SVN for this component
			if quoteSVN < tcbSVN {
				fmt.Printf(" FAIL (quote SVN too low)\n")
				allComponentsMatch = false
				break // Early exit - no need to check remaining components
			}
			fmt.Printf(" OK\n")
		}

		// Also check PCESVN if all components matched so far
		if allComponentsMatch {
			tcbPCESVN := level.TCB.PCESVN
			fmt.Printf("  PCESVN: quote=%d, TCB=%d", quotePCESVN, tcbPCESVN)

			if quotePCESVN < tcbPCESVN {
				fmt.Printf(" FAIL (quote PCESVN too low)\n")
				allComponentsMatch = false
			} else {
				fmt.Printf(" OK\n")
			}
		}

		// If all components match, this is our TCB level - return immediately
		if allComponentsMatch {
			fmt.Printf(" Matched TCB level %d: %s\n", levelIndex, level.TCBStatus)
			if len(level.AdvisoryIDs) > 0 {
				fmt.Printf("  Advisory IDs: %v\n", level.AdvisoryIDs)
			}
			return level.TCBStatus, level.AdvisoryIDs
		}
	}

	// No TCB level matched - platform is revoked or invalid
	fmt.Printf(" No TCB level matched - platform may be revoked\n")
	return "Revoked", []string{}
}
