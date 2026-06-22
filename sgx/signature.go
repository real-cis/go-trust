// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package sgx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"time"
)

// returns the canonical byte sequence that is covered by the quote
// signature:
func (q *ParsedQuote) SignedBytes() []byte {
	b := make([]byte, 0, 432)
	b = append(b, serializeQuoteHeader(q.Quote)...)
	b = append(b, serializeReportBody(&q.ReportBody)...)
	return b
}

// VerifySignature checks the ECDSA-P256 quote signature against the attestation
// key embedded in the quote's auth data.
func (q *ParsedQuote) VerifySignature() error {
	if len(q.AuthData.AttestationKey) != 64 {
		return fmt.Errorf("invalid attestation key length: %d (expected 64)", len(q.AuthData.AttestationKey))
	}

	pubKey, err := rawBytesToECDSAPublicKey(q.AuthData.AttestationKey)
	if err != nil {
		return fmt.Errorf("failed to parse attestation key: %w", err)
	}

	signed := q.SignedBytes()
	slog.Debug("signed data", "length", len(signed))

	return verifyECDSAP256(pubKey, signed, q.Signature[:64])
}

// Verify that QE Report's ReportData[0:32] == SHA-256(AttestationKey || QEAuthData).
// This binds the attestation key to the QE Report
func (q *ParsedQuote) VerifyQEReportData() error {
	// QEReport is a serialised ReportBody (384 bytes); ReportData starts at offset 320.
	if len(q.AuthData.QEReport) < 384 {
		return fmt.Errorf("QE report too short: %d bytes (expected 384)", len(q.AuthData.QEReport))
	}
	qeReportData := q.AuthData.QEReport[320:384]

	input := append(q.AuthData.AttestationKey, q.AuthData.QEAuthData...)
	expected := sha256.Sum256(input)
	slog.Debug("QE report data check", "expected", expected[:8], "actual", qeReportData[:8])

	if !bytes.Equal(expected[:], qeReportData[:32]) {
		return fmt.Errorf("QE report data mismatch: attestation key binding check failed")
	}
	if !bytes.Equal(qeReportData[32:], make([]byte, 32)) {
		return fmt.Errorf("QE report data upper 32 bytes are not zeroed")
	}

	return nil
}

func rawBytesToECDSAPublicKey(rawKey []byte) (*ecdsa.PublicKey, error) {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(rawKey[:32]),
		Y:     new(big.Int).SetBytes(rawKey[32:64]),
	}, nil
}

func serializeQuoteHeader(q *Quote) []byte {
	result := make([]byte, 0, 48)
	result = append(result, byte(q.Version), byte(q.Version>>8))
	result = append(result, byte(q.SignType), byte(q.SignType>>8))

	// Reserved field 4 bytes – TEE type is encoded here.
	// For SGX: 0x00000000, For TDX: 0x00000081.
	teeType := uint32(0)
	if q.Version == QuoteVersion4 {
		teeType = 0x81
	}
	result = append(result, byte(teeType), byte(teeType>>8), byte(teeType>>16), byte(teeType>>24))
	result = append(result, byte(q.QESVN), byte(q.QESVN>>8))
	result = append(result, byte(q.PCESVN), byte(q.PCESVN>>8))
	result = append(result, q.QEVendorID[:]...)
	result = append(result, q.UserData[:]...)

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
	result = append(result, body.MrEnclave[:]...)
	result = append(result, body.Reserved2[:]...)
	result = append(result, body.MrSigner[:]...)
	result = append(result, body.Reserved3[:]...)
	result = append(result, byte(body.ISVProdID), byte(body.ISVProdID>>8))
	result = append(result, byte(body.ISVSVN), byte(body.ISVSVN>>8))
	result = append(result, body.Reserved4[:]...)
	result = append(result, body.ReportData[:]...)
	return result
}

// verifies the ECDSA-P256 signature over the raw tcbInfo JSON bytes returned by Intel PCS.
//
// Intel signs the serialised tcbInfo JSON value with an ECDSA-P256 key whose certificate PEM is delivered in
// the Tcb-Info-Issuer-Chain response header. That certificate chains up to the embedded Intel SGX Root CA.
func VerifyTCBInfoSignature(rawTCBInfoJSON []byte, hexSig string, issuerChainHeader string) error {
	// 1. URL-decode and parse the TCB Signing certificate (always first in chain).
	chainPEM, err := url.PathUnescape(issuerChainHeader)
	if err != nil {
		return fmt.Errorf("failed to URL-decode TCB issuer chain header: %w", err)
	}
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("no TCB signing certificate found in issuer chain header")
	}
	signingCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse TCB signing certificate: %w", err)
	}
	slog.Debug("parsed TCB signing cert", "subject", signingCert.Subject.CommonName,
		"expires", signingCert.NotAfter.Format(time.RFC3339))

	// 2. Verify the signing cert chains up to the pinned Intel SGX Root CA.
	// CurrentTime zero value defaults to time.Now().
	rootPool := x509.NewCertPool()
	rootPool.AddCert(intelSGXRootCA())
	if _, err := signingCert.Verify(x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("TCB signing certificate chain verification failed: %w", err)
	}
	slog.Debug("TCB signing cert chain verified against Intel SGX Root CA")

	// 3. Hex-decode the signature (raw r ‖ s, 64 bytes), hash the payload, and verify.
	sigBytes, err := hex.DecodeString(hexSig)
	if err != nil {
		return fmt.Errorf("failed to hex-decode TCB info signature: %w", err)
	}
	ecPub, ok := signingCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("TCB signing certificate does not contain an ECDSA public key")
	}
	if err := verifyECDSAP256(ecPub, rawTCBInfoJSON, sigBytes); err != nil {
		return fmt.Errorf("TCB info signature: %w", err)
	}
	slog.Debug("TCB info signature verified")
	return nil
}

// verifyECDSAP256 hashes data with SHA-256 and checks the raw 64-byte ECDSA-P256
// signature (r || s) against pub.
func verifyECDSAP256(pub *ecdsa.PublicKey, data, rawSig []byte) error {
	if len(rawSig) < 64 {
		return fmt.Errorf("signature too short: %d bytes (expected 64)", len(rawSig))
	}
	hash := sha256.Sum256(data)
	r, s := new(big.Int).SetBytes(rawSig[:32]), new(big.Int).SetBytes(rawSig[32:64])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return fmt.Errorf("ECDSA-P256 signature verification failed")
	}
	return nil
}
