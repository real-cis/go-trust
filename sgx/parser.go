// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package sgx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
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
		slog.Debug("detected Open Enclave evidence format")
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

	slog.Debug("signature data length", "bytes", signDataLen)

	signatureDataBuf := make([]byte, signDataLen)
	reader.Read(signatureDataBuf)

	if err := parseSignatureData(signatureDataBuf, quote); err != nil {
		return nil, err
	}

	return quote, nil
}

func parseSignatureData(data []byte, quote *Quote) error {
	reader := bytes.NewReader(data)

	slog.Debug("parsing signature data", "bytes", len(data))

	// ISV signature 64 bytes - offset 0
	isvSignature := make([]byte, ecdsaP256SignatureSize)
	reader.Read(isvSignature)
	quote.Signature = isvSignature
	slog.Debug("read ISV signature", "offset", 0, "size", ecdsaP256SignatureSize, "remaining", reader.Len())

	// Attestation key 64 bytes - offset 64
	// This is the ECDSA P-256 public key (uncompressed format: X || Y)
	attKey := make([]byte, ecdsaP256PubKeySize)
	reader.Read(attKey)
	quote.AuthData.AttestationKey = attKey
	slog.Debug("read attestation key", "offset", 64, "size", ecdsaP256PubKeySize, "remaining", reader.Len())

	// QE Report 384 bytes - offset 128
	qeReport := make([]byte, qeReportSize)
	reader.Read(qeReport)
	quote.AuthData.QEReport = qeReport
	slog.Debug("read QE report", "offset", 128, "size", qeReportSize, "remaining", reader.Len())

	// QE Report Signature (64 bytes) - offset 512
	qeReportSig := make([]byte, qeReportSignatureSize)
	reader.Read(qeReportSig)
	quote.AuthData.QEReportSignature = qeReportSig
	slog.Debug("read QE report signature", "offset", 512, "size", qeReportSignatureSize, "remaining", reader.Len())

	// Total so far: 64 + 64 + 384 + 64 = 576 bytes
	// QE Auth Data Size (2 bytes)
	var qeAuthDataSize uint16
	if err := binary.Read(reader, binary.LittleEndian, &qeAuthDataSize); err != nil {
		return fmt.Errorf("failed to read QE auth data size: %w", err)
	}
	slog.Debug("QE auth data size", "offset", 576, "size", qeAuthDataSize)

	// QE Auth Data
	if qeAuthDataSize > 0 {
		if reader.Len() < int(qeAuthDataSize) {
			return fmt.Errorf("insufficient data for QE auth data: need %d, have %d", qeAuthDataSize, reader.Len())
		}

		qeAuthData := make([]byte, qeAuthDataSize)
		reader.Read(qeAuthData)
		quote.AuthData.QEAuthData = qeAuthData
		slog.Debug("read QE auth data", "offset", 578, "size", len(qeAuthData), "remaining", reader.Len(), "first16", qeAuthData[:min(16, len(qeAuthData))])
	}

	var certDataType uint16
	if err := binary.Read(reader, binary.LittleEndian, &certDataType); err != nil {
		return fmt.Errorf("failed to read cert data type: %w", err)
	}

	var certDataSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &certDataSize); err != nil {
		return fmt.Errorf("failed to read cert data size: %w", err)
	}

	slog.Debug("cert data header", "offset", 578+qeAuthDataSize, "type", certDataType, "typeName", certDataTypeName(certDataType), "size", certDataSize)

	// Cert Data (PEM certificates)
	if certDataSize > 0 {
		if reader.Len() < int(certDataSize) {
			return fmt.Errorf("insufficient data for cert data: need %d, have %d", certDataSize, reader.Len())
		}

		certData := make([]byte, certDataSize)
		reader.Read(certData)

		quote.AuthData.CertificationData = certData
		slog.Debug("extracted certification data", "bytes", len(certData))
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
