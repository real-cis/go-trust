// Package ccel provides CC Event Log parsing and handling.
// This file defines type aliases for backward compatibility with the tcg package.
package ccel

import (
	"gitlab.com/real-cis/cc/go-trust/internal/tcg"
)

// Algorithm constants - aliases for backward compatibility
const (
	TPM_ALG_RSA    = tcg.AlgRSA
	TPM_ALG_SHA1   = tcg.AlgSHA1
	TPM_ALG_SHA256 = tcg.AlgSHA256
	TPM_ALG_SHA384 = tcg.AlgSHA384
	TPM_ALG_SHA512 = tcg.AlgSHA512
	TPM_ALG_ECDSA  = tcg.AlgECDSA
)

// Event format constants - aliases for backward compatibility
const (
	TCG_PCCLIENT_FORMAT  = tcg.PCClientFormat
	TCG_CANONICAL_FORMAT = tcg.CanonicalFormat
)
