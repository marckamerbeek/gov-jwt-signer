// SPDX-License-Identifier: EUPL-1.2

package extauthsec

import "errors"

// Sentinel errors of the signer layer. Use errors.Is() to match against them.
var (
	// ErrNoSigningKey is returned when no signing key has been configured.
	ErrNoSigningKey = errors.New("extauthsec: geen ondertekensleutel geconfigureerd")

	// ErrUnsupportedAlgorithm is returned for an unsupported JWS algorithm.
	ErrUnsupportedAlgorithm = errors.New("extauthsec: niet-ondersteund ondertekenalgoritme")

	// ErrInvalidKey is returned when the key cannot be parsed or does not match the
	// chosen algorithm (e.g. an EC key with an RSA algorithm).
	ErrInvalidKey = errors.New("extauthsec: ongeldige of niet-passende sleutel")

	// ErrKeyAlgorithmMismatch is returned when the key type does not match the
	// selected algorithm.
	ErrKeyAlgorithmMismatch = errors.New("extauthsec: sleuteltype past niet bij algoritme")
)
