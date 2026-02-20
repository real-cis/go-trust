package sgx

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"gitlab.com/real-cis/cc/go-trust/sgx/tcb"
)

// interface for PCS clients (Intel PCS or local PCCS)
type Client interface {
	GetTCBInfo(fmspc string) (*tcb.TCBInfo, error)
	GetTDXTCBInfo(fmspc string) (*tcb.TCBInfo, error)
	GetRootCACRL() ([]byte, error)
	GetPCKCRL(ca string) ([]byte, error)
	GetQEIdentity() ([]byte, error)
}

type Config struct {
	BaseURL string
	APIKey  string
	Timeout time.Duration
}

type BaseClient struct {
	config     Config
	httpClient *http.Client
}

type PCSClient struct {
	*BaseClient
}

func NewPCSClient(baseURL string, apiKey string, timeout time.Duration) *PCSClient {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	baseConfig := Config{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Timeout: timeout,
	}

	return &PCSClient{
		BaseClient: NewBaseClient(baseConfig),
	}
}

func NewBaseClient(config Config) *BaseClient {
	return &BaseClient{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

func (c *BaseClient) Config() Config {
	return c.config
}

func (c *BaseClient) HTTPClient() *http.Client {
	return c.httpClient
}

// retrieves SGX TCB information for a given FMSPC
func (c *BaseClient) GetTCBInfo(fmspc string) (*tcb.TCBInfo, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/tcb?fmspc=%s", c.config.BaseURL, url.QueryEscape(fmspc))
	return c.fetchTCBInfo(u)
}

// retrieves TDX TCB information for a given FMSPC
func (c *BaseClient) GetTDXTCBInfo(fmspc string) (*tcb.TCBInfo, error) {
	u := fmt.Sprintf("%s/tdx/certification/v4/tcb?fmspc=%s", c.config.BaseURL, url.QueryEscape(fmspc))
	return c.fetchTCBInfo(u)
}

func (c *BaseClient) fetchTCBInfo(url string) (*tcb.TCBInfo, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.config.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.config.APIKey)
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

	var tcbInfoWrapper tcb.TCBInfoWrapper
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if err := json.Unmarshal(body, &tcbInfoWrapper); err != nil {
		return nil, fmt.Errorf("failed to decode TCB info: %w", err)
	}

	return &tcbInfoWrapper.TCBInfo, nil
}

func (c *BaseClient) GetRootCACRL() ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/rootcacrl", c.config.BaseURL)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.config.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.config.APIKey)
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

	return crl, nil
}

func (c *BaseClient) GetPCKCRL(ca string) ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/pckcrl", c.config.BaseURL)
	if ca != "" {
		u = fmt.Sprintf("%s?ca=%s", u, url.QueryEscape(ca))
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.config.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.config.APIKey)
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

	return crl, nil
}

// retrieves the Quoting Enclave identity
func (c *BaseClient) GetQEIdentity() ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/qe/identity", c.config.BaseURL)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.config.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.config.APIKey)
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
func (c *BaseClient) GetQVEIdentity() ([]byte, error) {
	u := fmt.Sprintf("%s/sgx/certification/v4/qve/identity", c.config.BaseURL)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.config.APIKey != "" {
		req.Header.Set("Ocp-Apim-Subscription-Key", c.config.APIKey)
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

// CertificateChain represents the certificate chain
type CertificateChain struct {
	RootCA         *x509.Certificate
	IntermediateCA *x509.Certificate
	PCKCert        *x509.Certificate
}
