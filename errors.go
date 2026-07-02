// SPDX-License-Identifier: EUPL-1.2

package jwtsigner

import "errors"

// Sentinel errors of the signer layer. Use errors.Is() to match against them.
var (
	// ErrNoSigningKey is returned when no signing key has been configured.
	ErrNoSigningKey = errors.New("jwtsigner: no signing key configured")

	// ErrUnsupportedAlgorithm is returned for an unsupported JWS algorithm.
	ErrUnsupportedAlgorithm = errors.New("jwtsigner: unsupported signing algorithm")

	// ErrInvalidKey is returned when the key cannot be parsed or does not match the
	// chosen algorithm (e.g. an EC key with an RSA algorithm).
	ErrInvalidKey = errors.New("jwtsigner: invalid or unsuitable key")

	// ErrKeyAlgorithmMismatch is returned when the key type does not match the
	// selected algorithm.
	ErrKeyAlgorithmMismatch = errors.New("jwtsigner: key type does not match algorithm")
)
