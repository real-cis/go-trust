// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package sgx

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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
	u := fmt.Sprintf("%s/sgx/certification/v4/tcb?fmspc=%s", c.BaseURL, url.QueryEscape(fmspc))
	return c.fetchTCBInfo(u)
}

// retrieves TDX TCB information for a given FMSPC
func (c *PCSClient) GetTDXTCBInfo(fmspc string) (*TCBInfo, error) {
	u := fmt.Sprintf("%s/tdx/certification/v4/tcb?fmspc=%s", c.BaseURL, url.QueryEscape(fmspc))
	return c.fetchTCBInfo(u)
}

func (c *PCSClient) fetchTCBInfo(url string) (*TCBInfo, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("client returned status %d: %s", resp.StatusCode, string(body))
	}

	var tcbInfoWrapper TCBInfoWrapper
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, &tcbInfoWrapper); err != nil {
		return nil, fmt.Errorf("failed to decode TCB info: %w", err)
	}

	return &tcbInfoWrapper.TCBInfo, nil
}

func (c *PCSClient) GetRootCACRL() ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/rootcacrl", c.BaseURL)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("client returned status %d: %s", resp.StatusCode, string(body))
	}

	crl, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL: %w", err)
	}

	decoded := make([]byte, hex.DecodedLen(len(crl)))
	n, err := hex.Decode(decoded, bytes.TrimSpace(crl))
	if err != nil {
		return nil, fmt.Errorf("failed to hex-decode CRL: %w", err)
	}
	slog.Debug("decoded root CA CRL", "size", n)
	return decoded[:n], nil
}

func (c *PCSClient) GetPCKCRL(ca string) ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/pckcrl", c.BaseURL)
	if ca != "" {
		u = fmt.Sprintf("%s?ca=%s", u, url.QueryEscape(ca))
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("client returned status %d: %s", resp.StatusCode, string(body))
	}

	crl, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL: %w", err)
	}

	decoded := make([]byte, hex.DecodedLen(len(crl)))
	n, err := hex.Decode(decoded, bytes.TrimSpace(crl))
	if err != nil {
		return nil, fmt.Errorf("failed to hex-decode CRL: %w", err)
	}
	slog.Debug("decoded PCK CRL", "size", n)
	return decoded[:n], nil
}

// retrieves the Quoting Enclave identity
func (c *PCSClient) GetQEIdentity() ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/qe/identity", c.BaseURL)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("client returned status %d: %s", resp.StatusCode, string(body))
	}

	identity, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read QE identity: %w", err)
	}

	return identity, nil
}

// GetQVEIdentity retrieves the Quote Verification Enclave identity
func (c *PCSClient) GetQVEIdentity() ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/qve/identity", c.BaseURL)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("client returned status %d: %s", resp.StatusCode, string(body))
	}

	identity, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read QVE identity: %w", err)
	}

	return identity, nil
}

type CertificateChain struct {
	RootCA         *x509.Certificate
	IntermediateCA *x509.Certificate
	PCKCert        *x509.Certificate
}
