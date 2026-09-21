// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package tdx

import (
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/client"
	"github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

type QuoteProvider interface {
	Generate(reportData [64]byte) ([]byte, error)
	Parse(rawQuote []byte) (*tdx.QuoteV4, error)
	Verify(rawQuote []byte) error
}

type DefaultQuoteProvider struct{}

func NewQuoteProvider() QuoteProvider {
	return &DefaultQuoteProvider{}
}

func (p *DefaultQuoteProvider) Generate(reportData [64]byte) ([]byte, error) {
	tdxQuoteProvider, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to get quote provider: %v", err)
	}
	quote, err := client.GetRawQuote(tdxQuoteProvider, reportData)
	if err != nil {
		return nil, fmt.Errorf("failed to get the report: %v", err)
	}
	return quote, nil
}

func (p *DefaultQuoteProvider) Parse(rawQuote []byte) (*tdx.QuoteV4, error) {
	quotev4, err := abi.QuoteToProto(rawQuote)
	if err != nil {
		return &tdx.QuoteV4{}, fmt.Errorf("parsing TDX quote: %w", err)
	}
	parsedBytes, ok := quotev4.(*tdx.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("failed to cast parsed quote to *tdx.QuoteV4")
	}
	return parsedBytes, nil
}

func (p *DefaultQuoteProvider) Verify(rawQuote []byte) error {
	opt := verify.DefaultOptions()
	opt.GetCollateral = true
	opt.CheckRevocations = true
	return verify.RawTdxQuote(rawQuote, opt)
}
