// Copyright 2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package tcg

// Digest represents a TCG digest with its algorithm identifier.
type Digest struct {
	AlgID Algorithm
	Hash  []byte
}

// NewDigest creates a new Digest with the given algorithm and hash.
func NewDigest(alg Algorithm, hash []byte) Digest {
	return Digest{
		AlgID: alg,
		Hash:  hash,
	}
}
