// SPDX-License-Identifier: EUPL-1.2

package extauthsec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Signer is the cryptographic core of the module. It signs JWTs with a single
// asymmetric key and publishes the corresponding public key as a JWKS.
//
// A Signer is immutable after construction and safe for concurrent use by
// multiple goroutines.
type Signer struct {
	key            crypto.Signer
	method         jwt.SigningMethod
	algorithm      Algorithm
	keyID          string
	issuer         string
	defaultTTL     time.Duration
	now            func() time.Time
	jwk            JWK
	tokenTypeClaim string
}

// NewSigner builds a Signer from the given options. At minimum a signing key
// (WithSigningKeyPEM or WithSigningKeyFile) and an issuer (WithIssuer) are
// required.
func NewSigner(opts ...Option) (*Signer, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.issuer == "" {
		return nil, fmt.Errorf("extauthsec: WithIssuer is required")
	}
	if len(cfg.keyPEM) == 0 {
		return nil, ErrNoSigningKey
	}

	key, err := parsePrivateKeyPEM(cfg.keyPEM)
	if err != nil {
		return nil, err
	}

	method, err := signingMethod(cfg.algorithm)
	if err != nil {
		return nil, err
	}
	if err := checkKeyMatchesAlgorithm(key, cfg.algorithm); err != nil {
		return nil, err
	}

	jwk, err := publicJWK(key, cfg.algorithm, cfg.keyID)
	if err != nil {
		return nil, err
	}

	return &Signer{
		key:            key,
		method:         method,
		algorithm:      cfg.algorithm,
		keyID:          jwk.Kid,
		issuer:         cfg.issuer,
		defaultTTL:     cfg.defaultTTL,
		now:            cfg.now,
		jwk:            jwk,
		tokenTypeClaim: cfg.tokenTypeClaim,
	}, nil
}

// Sign signs the given claims into a compact JWS (a JWT). The protected header
// contains alg, typ=JWT and kid.
func (s *Signer) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(s.method, claims)
	token.Header["typ"] = "JWT"
	token.Header["kid"] = s.keyID
	return token.SignedString(s.key)
}

// Issuer returns the configured iss claim value.
func (s *Signer) Issuer() string { return s.issuer }

// Algorithm returns the configured signing algorithm.
func (s *Signer) Algorithm() Algorithm { return s.algorithm }

// KeyID returns the kid placed in every token header.
func (s *Signer) KeyID() string { return s.keyID }

// DefaultTTL returns the default validity duration.
func (s *Signer) DefaultTTL() time.Duration { return s.defaultTTL }

// TokenTypeClaim returns the name of the private claim that carries the token
// type (default "token_type", see WithTokenTypeClaim).
func (s *Signer) TokenTypeClaim() string { return s.tokenTypeClaim }

// Now returns the current time according to the configured clock.
func (s *Signer) Now() time.Time { return s.now() }

// NewJTI generates a random, intended-to-be-unique token identifier (jti,
// RFC 7519 §4.1.7) of 128 bits, base64url-encoded.
func (s *Signer) NewJTI() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("extauthsec: could not generate jti: %w", err)
	}
	return b64u(buf[:]), nil
}

// JWKS returns the JSON Web Key Set containing the public signing key.
func (s *Signer) JWKS() JWKS {
	return JWKS{Keys: []JWK{s.jwk}}
}

// JWKSJSON returns the JWKS as JSON, ready to serve at e.g.
// /.well-known/jwks.json.
func (s *Signer) JWKSJSON() ([]byte, error) {
	return json.Marshal(s.JWKS())
}

func signingMethod(alg Algorithm) (jwt.SigningMethod, error) {
	switch alg {
	case RS256:
		return jwt.SigningMethodRS256, nil
	case RS384:
		return jwt.SigningMethodRS384, nil
	case RS512:
		return jwt.SigningMethodRS512, nil
	case PS256:
		return jwt.SigningMethodPS256, nil
	case PS384:
		return jwt.SigningMethodPS384, nil
	case PS512:
		return jwt.SigningMethodPS512, nil
	case ES256:
		return jwt.SigningMethodES256, nil
	case ES384:
		return jwt.SigningMethodES384, nil
	case ES512:
		return jwt.SigningMethodES512, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, alg)
	}
}

func checkKeyMatchesAlgorithm(key crypto.Signer, alg Algorithm) error {
	switch key.Public().(type) {
	case *rsa.PublicKey:
		if !alg.isRSA() {
			return fmt.Errorf("%w: RSA key with algorithm %q", ErrKeyAlgorithmMismatch, alg)
		}
	case *ecdsa.PublicKey:
		if !alg.isEC() {
			return fmt.Errorf("%w: EC key with algorithm %q", ErrKeyAlgorithmMismatch, alg)
		}
	default:
		return fmt.Errorf("%w: unknown public key type", ErrInvalidKey)
	}
	return nil
}
