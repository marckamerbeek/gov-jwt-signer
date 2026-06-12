// SPDX-License-Identifier: EUPL-1.2

package extauthsec

import (
	"fmt"
	"os"
	"time"
)

// Option configures a Signer via NewSigner.
type Option func(*config) error

type config struct {
	issuer     string
	algorithm  Algorithm
	keyPEM     []byte
	keyID      string
	defaultTTL time.Duration
	now        func() time.Time
}

func defaultConfig() *config {
	return &config{
		// RS256 is the baseline of the NL GOV Assurance profile for OAuth 2.0 and
		// offers the broadest interoperability within government chains. Override
		// with WithAlgorithm (PS256 for extra hardening).
		algorithm:  RS256,
		defaultTTL: 5 * time.Minute,
		now:        time.Now,
	}
}

// WithIssuer sets the iss claim (RFC 7519 §4.1.1) placed in every token.
func WithIssuer(iss string) Option {
	return func(c *config) error {
		if iss == "" {
			return fmt.Errorf("extauthsec: issuer mag niet leeg zijn")
		}
		c.issuer = iss
		return nil
	}
}

// WithAlgorithm chooses the JWS signing algorithm. It must match the key type.
func WithAlgorithm(alg Algorithm) Option {
	return func(c *config) error {
		if !alg.supported() {
			return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
		}
		c.algorithm = alg
		return nil
	}
}

// WithSigningKeyPEM sets the PEM-encoded private key (PKCS#8, PKCS#1 or SEC1).
func WithSigningKeyPEM(pemBytes []byte) Option {
	return func(c *config) error {
		if len(pemBytes) == 0 {
			return ErrNoSigningKey
		}
		c.keyPEM = pemBytes
		return nil
	}
}

// WithSigningKeyFile loads the PEM-encoded private key from a file path.
func WithSigningKeyFile(path string) Option {
	return func(c *config) error {
		b, err := os.ReadFile(path) //nolint:gosec // path comes from the calling configuration
		if err != nil {
			return fmt.Errorf("extauthsec: kan sleutelbestand niet lezen: %w", err)
		}
		c.keyPEM = b
		return nil
	}
}

// WithKeyID sets the kid (key ID). If it is not set, the Signer computes the kid
// as the RFC 7638 JWK thumbprint, so that verifiers can select the right key.
func WithKeyID(kid string) Option {
	return func(c *config) error {
		c.keyID = kid
		return nil
	}
}

// WithDefaultTTL sets the default validity duration for tokens for which the
// caller does not provide an explicit TTL.
func WithDefaultTTL(ttl time.Duration) Option {
	return func(c *config) error {
		if ttl <= 0 {
			return fmt.Errorf("extauthsec: TTL moet positief zijn")
		}
		c.defaultTTL = ttl
		return nil
	}
}

// WithClock injects a clock. Intended for tests; defaults to time.Now.
func WithClock(now func() time.Time) Option {
	return func(c *config) error {
		if now == nil {
			return fmt.Errorf("extauthsec: klok mag niet nil zijn")
		}
		c.now = now
		return nil
	}
}
