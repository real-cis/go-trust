package sgx

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	QuoteVersion3 = 3
	QuoteVersion4 = 4

	SignTypeECDSA_P256 = 2
	SignTypeECDSA_P384 = 3

	oeFormatVersion         = 1
	oeEvidenceTypeSGXRemote = 2
	oeHeaderSize            = 16

	ecdsaP256SignatureSize = 64
	ecdsaP256PubKeySize    = 64
	qeReportSize           = 384
	qeReportSignatureSize  = 64
)

const (
	CertDataTypePPIDCleartext        = 1
	CertDataTypePPIDEncryptedRSA2048 = 2
	CertDataTypePPIDEncryptedRSA3072 = 3
	CertDataTypePCKLeafCert          = 4
	CertDataTypePCKCertChain         = 5
	CertDataTypeQEReportSignature    = 6
	CertDataTypePlatformManifest     = 7
)

func ParseQuote(data []byte) (*ParsedQuote, error) {
	if len(data) < 436 {
		return nil, fmt.Errorf("quote data too short: %d bytes", len(data))
	}

	quoteData, isOEFormat, err := unwrapOpenEnclaveEvidence(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap evidence: %w", err)
	}

	if isOEFormat {
		fmt.Printf("Detected Open Enclave evidence format (ego/edgelesssys)\n")
	}

	raw, err := parseRawQuote(quoteData)
	if err != nil {
		return nil, err
	}
	return &ParsedQuote{Quote: raw}, nil
}

func unwrapOpenEnclaveEvidence(data []byte) ([]byte, bool, error) {
	if len(data) < oeHeaderSize {
		return data, false, nil
	}

	reader := bytes.NewReader(data)

	var formatVersion, evidenceType uint32
	var evidenceSize uint64

	binary.Read(reader, binary.LittleEndian, &formatVersion)
	binary.Read(reader, binary.LittleEndian, &evidenceType)
	binary.Read(reader, binary.LittleEndian, &evidenceSize)

	if formatVersion == oeFormatVersion && evidenceType == oeEvidenceTypeSGXRemote {
		if len(data) < oeHeaderSize+int(evidenceSize) {
			return nil, false, fmt.Errorf("OE evidence size mismatch")
		}
		return data[oeHeaderSize : oeHeaderSize+evidenceSize], true, nil
	}

	return data, false, nil
}

func parseRawQuote(data []byte) (*Quote, error) {
	reader := bytes.NewReader(data)
	quote := &Quote{}

	// Header 48 bytes
	binary.Read(reader, binary.LittleEndian, &quote.Version)

	switch quote.Version {
	case QuoteVersion3:
		quote.QuoteType = QuoteSGX
	case QuoteVersion4:
		quote.QuoteType = QuoteTDX
	default:
		return nil, fmt.Errorf("unsupported quote version: %d", quote.Version)
	}

	binary.Read(reader, binary.LittleEndian, &quote.SignType)

	var reserved [4]byte
	binary.Read(reader, binary.LittleEndian, &reserved)

	binary.Read(reader, binary.LittleEndian, &quote.QESVN)
	binary.Read(reader, binary.LittleEndian, &quote.PCESVN)

	binary.Read(reader, binary.LittleEndian, &quote.QEVendorID)
	binary.Read(reader, binary.LittleEndian, &quote.UserData)

	// Report body 384 bytes
	if err := parseReportBody(reader, &quote.ReportBody); err != nil {
		return nil, err
	}

	// Signature data length
	var signDataLen uint32
	binary.Read(reader, binary.LittleEndian, &signDataLen)

	fmt.Printf("Debug: Signature data length: %d bytes\n", signDataLen)

	signatureDataBuf := make([]byte, signDataLen)
	reader.Read(signatureDataBuf)

	if err := parseSignatureData(signatureDataBuf, quote); err != nil {
		return nil, err
	}

	return quote, nil
}

func parseSignatureData(data []byte, quote *Quote) error {
	reader := bytes.NewReader(data)

	fmt.Printf("\nDebug: Parsing signature data (%d bytes)\n", len(data))

	// ISV signature 64 bytes - offset 0
	isvSignature := make([]byte, ecdsaP256SignatureSize)
	reader.Read(isvSignature)
	quote.Signature = isvSignature
	fmt.Printf("Debug: [0] ISV signature %d bytes, remaining: %d\n", ecdsaP256SignatureSize, reader.Len())

	// Attestation key 64 bytes - offset 64
	// This is the ECDSA P-256 public key (uncompressed format: X || Y)
	attKey := make([]byte, ecdsaP256PubKeySize)
	reader.Read(attKey)
	quote.AuthData.AttestationKey = attKey
	fmt.Printf("Debug: [64] Attestation key %d bytes, remaining: %d\n", ecdsaP256PubKeySize, reader.Len())

	// QE Report 384 bytes - offset 128
	qeReport := make([]byte, qeReportSize)
	reader.Read(qeReport)
	quote.AuthData.QEReport = qeReport
	fmt.Printf("Debug: [128] QE report %d bytes, remaining: %d\n", qeReportSize, reader.Len())

	// QE Report Signature (64 bytes) - offset 512
	qeReportSig := make([]byte, qeReportSignatureSize)
	reader.Read(qeReportSig)
	quote.AuthData.QEReportSignature = qeReportSig
	fmt.Printf("Debug: [512] QE report signature %d bytes, remaining: %d\n", qeReportSignatureSize, reader.Len())

	// Total so far: 64 + 64 + 384 + 64 = 576 bytes
	// QE Auth Data Size (2 bytes)
	var qeAuthDataSize uint16
	if err := binary.Read(reader, binary.LittleEndian, &qeAuthDataSize); err != nil {
		return fmt.Errorf("failed to read QE auth data size: %w", err)
	}
	fmt.Printf("Debug: [576] QE auth data size: %d bytes\n", qeAuthDataSize)

	// QE Auth Data
	if qeAuthDataSize > 0 {
		if reader.Len() < int(qeAuthDataSize) {
			return fmt.Errorf("insufficient data for QE auth data: need %d, have %d", qeAuthDataSize, reader.Len())
		}

		qeAuthData := make([]byte, qeAuthDataSize)
		reader.Read(qeAuthData)
		quote.AuthData.QEAuthData = qeAuthData
		fmt.Printf("Debug: [578] Read QE auth data (%d bytes), remaining: %d\n", len(qeAuthData), reader.Len())
		fmt.Printf("Debug: First 16 bytes of QE auth data: %x\n", qeAuthData[:min(16, len(qeAuthData))])
	}

	var certDataType uint16
	if err := binary.Read(reader, binary.LittleEndian, &certDataType); err != nil {
		return fmt.Errorf("failed to read cert data type: %w", err)
	}

	var certDataSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &certDataSize); err != nil {
		return fmt.Errorf("failed to read cert data size: %w", err)
	}

	fmt.Printf("Debug: [%d] Cert data type: %d (%s), size: %d bytes\n",
		578+qeAuthDataSize, certDataType, certDataTypeName(certDataType), certDataSize)

	// Cert Data (PEM certificates)
	if certDataSize > 0 {
		if reader.Len() < int(certDataSize) {
			return fmt.Errorf("insufficient data for cert data: need %d, have %d", certDataSize, reader.Len())
		}

		certData := make([]byte, certDataSize)
		reader.Read(certData)

		quote.AuthData.CertificationData = certData
		fmt.Printf("Debug: Successfully extracted certification data (%d bytes)\n", len(certData))
	}

	return nil
}

func certDataTypeName(certType uint16) string {
	switch certType {
	case CertDataTypePPIDCleartext:
		return "PPID Cleartext"
	case CertDataTypePPIDEncryptedRSA2048:
		return "PPID Encrypted RSA-2048"
	case CertDataTypePPIDEncryptedRSA3072:
		return "PPID Encrypted RSA-3072"
	case CertDataTypePCKLeafCert:
		return "PCK Leaf Certificate"
	case CertDataTypePCKCertChain:
		return "PCK Certificate Chain"
	case CertDataTypeQEReportSignature:
		return "QE Report Signature"
	case CertDataTypePlatformManifest:
		return "Platform Manifest"
	default:
		return fmt.Sprintf("Unknown (%d)", certType)
	}
}

func parseReportBody(reader *bytes.Reader, body *ReportBody) error {
	binary.Read(reader, binary.LittleEndian, &body.CPUSVN)
	binary.Read(reader, binary.LittleEndian, &body.MiscSelect)
	binary.Read(reader, binary.LittleEndian, &body.Reserved1)
	binary.Read(reader, binary.LittleEndian, &body.Attributes)
	binary.Read(reader, binary.LittleEndian, &body.MrEnclave)
	binary.Read(reader, binary.LittleEndian, &body.Reserved2)
	binary.Read(reader, binary.LittleEndian, &body.MrSigner)
	binary.Read(reader, binary.LittleEndian, &body.Reserved3)
	binary.Read(reader, binary.LittleEndian, &body.ISVProdID)
	binary.Read(reader, binary.LittleEndian, &body.ISVSVN)
	binary.Read(reader, binary.LittleEndian, &body.Reserved4)
	binary.Read(reader, binary.LittleEndian, &body.ReportData)
	return nil
}
