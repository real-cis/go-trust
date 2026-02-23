// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package sgx

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"
)

var (
	// SGX Extension OID: 1.2.840.113741.1.13.1
	sgxExtensionOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	// FMSPC OID: 1.2.840.113741.1.13.1.4
	fmspcOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
)

// CertChain parses and returns the PCK certificate chain embedded in the quote's
// auth data.
func (q *ParsedQuote) CertChain() ([]*x509.Certificate, error) {
	q.certChainOnce.Do(func() {
		q.certChainVal, q.certChainErr = parseCertChain(q.AuthData.CertificationData)
	})
	return q.certChainVal, q.certChainErr
}

// PCKCert returns the leaf PCK certificate from the quote's cert chain.
func (q *ParsedQuote) PCKCert() (*x509.Certificate, error) {
	chain, err := q.CertChain()
	if err != nil {
		return nil, err
	}
	return chain[0], nil
}

// FMSPC extracts the 6-byte FMSPC value from the SGX extension in the PCK leaf certificate.
func (q *ParsedQuote) FMSPC() (string, error) {
	q.fmspcOnce.Do(func() {
		q.fmspcVal, q.fmspcErr = q.extractFMSPC()
	})
	return q.fmspcVal, q.fmspcErr
}

func (q *ParsedQuote) extractFMSPC() (string, error) {
	pckCert, err := q.PCKCert()
	if err != nil {
		return "", err
	}

	for _, ext := range pckCert.Extensions {
		if !ext.Id.Equal(sgxExtensionOID) {
			continue
		}
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

// parseCertChain decodes PEM (or raw DER) certificate data into an ordered
// slice
func parseCertChain(certData []byte) ([]*x509.Certificate, error) {
	if len(certData) == 0 {
		return nil, fmt.Errorf("no certification data in quote")
	}

	// Try PEM first.
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

	// Fall back to raw DER (single cert, then multiple).
	if cert, err := x509.ParseCertificate(certData); err == nil {
		return []*x509.Certificate{cert}, nil
	}
	certs, err := x509.ParseCertificates(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate data: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in certification data")
	}
	return certs, nil
}

// verifyCertChain verifies that pckCert chains up to the Intel SGX Root CA
// through the provided intermediates.
func verifyCertChain(pckCert *x509.Certificate, intermediates []*x509.Certificate, rootCRL, pckCRL []byte) error {
	if pckCert == nil {
		return fmt.Errorf("PCK certificate is nil")
	}

	now := time.Now()
	if now.Before(pckCert.NotBefore) || now.After(pckCert.NotAfter) {
		return fmt.Errorf("PCK certificate is not valid at current time")
	}

	slog.Debug("PCK certificate is valid", "expires", pckCert.NotAfter.Format(time.RFC3339))

	rootPool := x509.NewCertPool()
	rootPool.AddCert(intelSGXRootCA())

	intermediatePool := x509.NewCertPool()
	for _, c := range intermediates {
		intermediatePool.AddCert(c)
		slog.Debug("added intermediate CA", "commonName", c.Subject.CommonName)
	}

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
	slog.Debug("certificate chain verified", "chainLength", len(chains[0]))

	// Check CRLs for revocation.
	if len(rootCRL) > 0 && len(pckCRL) > 0 {
		slog.Debug("checking CRLs", "rootCRLSize", len(rootCRL), "pckCRLSize", len(pckCRL))
		now := time.Now()

		parsedRootCRL, err := x509.ParseRevocationList(rootCRL)
		if err != nil {
			return fmt.Errorf("failed to parse root CRL: %w", err)
		}
		if err := parsedRootCRL.CheckSignatureFrom(intelSGXRootCA()); err != nil {
			return fmt.Errorf("root CRL signature invalid: %w", err)
		}
		if now.After(parsedRootCRL.NextUpdate) {
			return fmt.Errorf("root CRL has expired at %s", parsedRootCRL.NextUpdate)
		}

		parsedPCKCRL, err := x509.ParseRevocationList(pckCRL)
		if err != nil {
			return fmt.Errorf("failed to parse PCK CRL: %w", err)
		}
		if len(intermediates) == 0 {
			return fmt.Errorf("no intermediate CA to verify PCK CRL signature")
		}
		if err := parsedPCKCRL.CheckSignatureFrom(intermediates[0]); err != nil {
			return fmt.Errorf("PCK CRL signature invalid: %w", err)
		}
		if now.After(parsedPCKCRL.NextUpdate) {
			return fmt.Errorf("PCK CRL has expired at %s", parsedPCKCRL.NextUpdate)
		}

		// Check intermediates against root CRL
		for _, ic := range intermediates {
			if err := checkRevocation(parsedRootCRL, ic); err != nil {
				return err
			}
		}
		// Check PCK leaf cert against PCK CRL
		if err := checkRevocation(parsedPCKCRL, pckCert); err != nil {
			return err
		}
	}
	return nil
}

func checkRevocation(crl *x509.RevocationList, cert *x509.Certificate) error {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return fmt.Errorf("certificate %s (serial %s) has been revoked",
				cert.Subject.CommonName, cert.SerialNumber)
		}
	}
	return nil
}

// intelSGXRootCA returns the well-known Intel SGX Root CA (valid until 2049).
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
