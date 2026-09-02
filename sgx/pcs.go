// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package sgx

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// interface for PCS clients (Intel PCS or local PCCS)
type Client interface {
	GetTCBInfo(fmspc string) (*TCBInfo, error)
	GetTDXTCBInfo(fmspc string) (*TCBInfo, error)
	GetRootCACRL() ([]byte, error)
	GetPCKCRL(ca string) ([]byte, error)
	GetQEIdentity() ([]byte, error)
}

type PCSClient struct {
	BaseURL    string
	APIKey     string
	httpClient *http.Client
}

// Creates a new PCSClient with the given base URL, API key, and timeout.
// baseURL - PCCS service or Intel PCS API endpoint (https://api.trustedservices.intel.com)
func NewPCSClient(baseURL string, apiKey string, timeout time.Duration) *PCSClient {
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &PCSClient{
		BaseURL: baseURL,
		APIKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *PCSClient) HTTPClient() *http.Client {
	return c.httpClient
}

// retrieves SGX TCB information for a given FMSPC
func (c *PCSClient) GetTCBInfo(fmspc string) (*TCBInfo, error) {
	return c.GetTCBInfoFor("sgx", fmspc, "")
}

// retrieves TDX TCB information for a given FMSPC
func (c *PCSClient) GetTDXTCBInfo(fmspc string) (*TCBInfo, error) {
	return c.GetTCBInfoFor("tdx", fmspc, "")
}

func (c *PCSClient) fetchTCBInfo(url string) (*TCBInfo, error) {
	header, body, err := c.fetch(url)
	if err != nil {
		return nil, err
	}

	var wrapper SignedTCBInfo
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to decode TCB info response: %w", err)
	}

	// Signature roots up to the pinned Intel SGX Root CA via the issuer chain.
	issuerChain := header.Get("Tcb-Info-Issuer-Chain")
	if issuerChain == "" {
		slog.Warn("Tcb-Info-Issuer-Chain header absent; skipping TCB info signature verification")
	} else {
		if err := VerifyTCBInfoSignature(wrapper.TCBInfo, wrapper.Signature, issuerChain); err != nil {
			return nil, fmt.Errorf("TCB info signature verification failed: %w", err)
		}
	}

	var tcbInfo TCBInfo
	if err := json.Unmarshal(wrapper.TCBInfo, &tcbInfo); err != nil {
		return nil, fmt.Errorf("failed to decode TCB info: %w", err)
	}

	return &tcbInfo, nil
}

func (c *PCSClient) GetRootCACRL() ([]byte, error) {
	// /rootcacrl is PCCS-only, not for Intel PCS, so fall back to the CRL
	// distribution point published in the pinned root cert (raw DER).
	u := fmt.Sprintf("%s/sgx/certification/v4/rootcacrl", c.BaseURL)
	_, crl, err := c.fetch(u)
	if err != nil {
		cdp := intelSGXRootCACDP()
		if cdp == "" {
			return nil, fmt.Errorf("rootcacrl endpoint failed and no CDP in root cert: %w", err)
		}
		slog.Debug("rootcacrl unavailable, using root CA CDP", "cdp", cdp, "err", err)
		if _, crl, err = c.fetch(cdp); err != nil {
			return nil, fmt.Errorf("failed to fetch root CA CRL from CDP %s: %w", cdp, err)
		}
	}
	return decodeCRL(crl)
}

func (c *PCSClient) GetPCKCRL(ca string) ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/pckcrl", c.BaseURL)
	if ca != "" {
		u = fmt.Sprintf("%s?ca=%s", u, url.QueryEscape(ca))
	}

	_, crl, err := c.fetch(u)
	if err != nil {
		return nil, err
	}
	return decodeCRL(crl)
}

func (c *PCSClient) fetch(u string) (http.Header, []byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("client returned status %d: %s", resp.StatusCode, string(body))
	}
	return resp.Header, body, nil
}

// decodeCRL normalizes a CRL response to raw DER, accepting PEM (Intel pckcrl),
// hex (PCCS), or raw DER (Intel root CDP).
func decodeCRL(b []byte) ([]byte, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("empty CRL response")
	}
	if block, _ := pem.Decode(b); block != nil {
		return block.Bytes, nil
	}
	if decoded, err := hex.DecodeString(string(b)); err == nil {
		return decoded, nil
	}
	return b, nil // already raw DER
}

// retrieves the Quoting Enclave identity
func (c *PCSClient) GetQEIdentity() ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/qe/identity", c.BaseURL)
	_, body, err := c.fetch(u)
	return body, err
}

// GetQVEIdentity retrieves the Quote Verification Enclave identity
func (c *PCSClient) GetQVEIdentity() ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/qve/identity", c.BaseURL)
	_, body, err := c.fetch(u)
	return body, err
}

// TCBEvalNumbers lists the TCB Recovery events Intel currently publishes
// collateral for
type TCBEvalNumbers struct {
	ID          string         `json:"id"`
	Version     int            `json:"version"`
	IssueDate   string         `json:"issueDate"`
	NextUpdate  string         `json:"nextUpdate"`
	EvalNumbers []TCBEvalEntry `json:"tcbEvalNumbers"`
}

type TCBEvalEntry struct {
	Number            int    `json:"tcbEvaluationDataNumber"`
	RecoveryEventDate string `json:"tcbRecoveryEventDate"`
	TCBDate           string `json:"tcbDate"`
}

type signedEvalNumbers struct {
	EvalNumbers TCBEvalNumbers `json:"tcbEvaluationDataNumbers"`
	Signature   string         `json:"signature"`
}

// GetTCBInfoFor retrieves TCB Info for a TEE ("sgx" or "tdx")
func (c *PCSClient) GetTCBInfoFor(tee, fmspc, update string) (*TCBInfo, error) {
	q := url.Values{"fmspc": {fmspc}}
	if update != "" {
		q.Set("update", update)
	}
	return c.fetchTCBInfo(c.tcbURL(tee, q))
}

// GetTCBInfoAt retrieves TCB Info for a specific TCB evaluation data number.
func (c *PCSClient) GetTCBInfoAt(tee, fmspc string, evalNum int) (*TCBInfo, error) {
	q := url.Values{"fmspc": {fmspc}, "tcbEvaluationDataNumber": {strconv.Itoa(evalNum)}}
	tcb, err := c.fetchTCBInfo(c.tcbURL(tee, q))
	if err != nil {
		return nil, err
	}

	if tcb.TcbEvalNum != evalNum {
		return nil, fmt.Errorf("%s ignored tcbEvaluationDataNumber: asked for %d, got %d",
			c.BaseURL, evalNum, tcb.TcbEvalNum)
	}
	return tcb, nil
}

// GetTCBEvaluationDataNumbers lists the published TCB Recovery events for a TEE.
func (c *PCSClient) GetTCBEvaluationDataNumbers(tee string) (*TCBEvalNumbers, error) {
	u := fmt.Sprintf("%s/%s/certification/v4/tcbevaluationdatanumbers", c.BaseURL, tee)
	_, body, err := c.fetch(u)
	if err != nil {
		return nil, err
	}
	var wrapper signedEvalNumbers
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to decode TCB evaluation data numbers: %w", err)
	}
	return &wrapper.EvalNumbers, nil
}

// GetPCKCert retrieves the PCK certificate for a platform from a PCCS
func (c *PCSClient) GetPCKCert(qeid, cpusvn, pcesvn, pceid, encPPID string) (*x509.Certificate, error) {
	q := url.Values{
		"qeid":           {qeid},
		"cpusvn":         {cpusvn},
		"pcesvn":         {pcesvn},
		"pceid":          {pceid},
		"encrypted_ppid": {encPPID},
	}
	u := fmt.Sprintf("%s/sgx/certification/v4/pckcert?%s", c.BaseURL, q.Encode())
	_, body, err := c.fetch(u)
	if err != nil {
		return nil, err
	}
	// Intel PCS percent-encodes the PEM; a PCCS may return it verbatim.
	text := string(body)
	if !strings.Contains(text, "BEGIN CERTIFICATE") {
		if decoded, err := url.PathUnescape(text); err == nil {
			text = decoded
		}
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, fmt.Errorf("PCCS did not return a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (c *PCSClient) tcbURL(tee string, q url.Values) string {
	return fmt.Sprintf("%s/%s/certification/v4/tcb?%s", c.BaseURL, tee, q.Encode())
}
