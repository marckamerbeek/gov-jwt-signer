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

	// ErrJWKWithoutAlg is returned when a JWK in the set omits the alg field.
	// Without alg the verifier cannot enforce an algorithm allowlist.
	ErrJWKWithoutAlg = errors.New("jwtsigner: JWK without alg in the set")

	// ErrWeakSigningKey is returned when the private key is below the minimum
	// strength (RSA < 2048 bits, or EC on a non-approved curve).
	ErrWeakSigningKey = errors.New("jwtsigner: signing key below minimum strength")

	// ErrDuplicateKeyID is returned when a JWKS contains the same kid more than once.
	ErrDuplicateKeyID = errors.New("jwtsigner: duplicate kid in JWKS")
)
