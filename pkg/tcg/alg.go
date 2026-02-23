// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

// Package tcg provides common TCG (Trusted Computing Group) types and constantspackage tcg
// Ref: https://trustedcomputinggroup.org/wp-content/uploads/TCG-_Algorithm_Registry_r1p32_pub.pdf

package tcg

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// TPM algorithm identifiers as defined by TCG.
type Algorithm int32

const (
	AlgError  Algorithm = 0x0
	AlgRSA    Algorithm = 0x1
	AlgSHA1   Algorithm = 0x4
	AlgSHA256 Algorithm = 0xB
	AlgSHA384 Algorithm = 0xC
	AlgSHA512 Algorithm = 0xD
	AlgECDSA  Algorithm = 0x18
)

func (alg Algorithm) String() string {
	switch alg {
	case AlgError:
		return "TPM_ALG_ERROR"
	case AlgRSA:
		return "TPM_ALG_RSA"
	case AlgSHA1:
		return "TPM_ALG_SHA1"
	case AlgSHA256:
		return "TPM_ALG_SHA256"
	case AlgSHA384:
		return "TPM_ALG_SHA384"
	case AlgSHA512:
		return "TPM_ALG_SHA512"
	case AlgECDSA:
		return "TPM_ALG_ECDSA"
	}
	return ""
}

// DigestSize returns the digest size in bytes for the given algorithm.
// Returns 0 if the algorithm is not a hash algorithm.
// func (alg Algorithm) DigestSize() int {
// 	return DigestSizeTable[alg]
// }

// DigestSizeTable maps hash algorithms to their digest sizes in bytes.
var DigestSizeTable = map[Algorithm]int{
	AlgSHA1:   20,
	AlgSHA256: 32,
	AlgSHA384: 48,
	AlgSHA512: 64,
}

// Returns new hash.Hash for the given algorithm.
// Returns nil if the algorithm is not a supported hash algorithm.
func (alg Algorithm) NewHash() hash.Hash {
	switch alg {
	case AlgSHA1:
		return sha1.New()
	case AlgSHA256:
		return sha256.New()
	case AlgSHA384:
		return sha512.New384()
	case AlgSHA512:
		return sha512.New()
	}
	return nil
}
