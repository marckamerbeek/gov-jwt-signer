// SPDX-License-Identifier: EUPL-1.2

package jwtsigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier validates JWTs against a JSON Web Key Set. The module primarily signs,
// but this Verifier enables self-testing of issued tokens and lightweight
// verification on the consumer side.
//
// Production verifiers in other languages/services use their own JOSE library;
// this Verifier demonstrates the expected behaviour (kid matching, alg allowlist,
// exp/nbf, iss/aud checking).
type Verifier struct {
	keys             map[string]JWK
	allowedAlgs      []string
	expectedIssuer   string
	expectedAudience string
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithExpectedIssuer enforces that the iss claim matches exactly.
func WithExpectedIssuer(iss string) VerifierOption {
	return func(v *Verifier) { v.expectedIssuer = iss }
}

// WithExpectedAudience enforces that the aud claim contains the given value.
func WithExpectedAudience(aud string) VerifierOption {
	return func(v *Verifier) { v.expectedAudience = aud }
}

// NewVerifier builds a Verifier from a JWKS. Only the algorithms indicated in the
// JWKS are allowed (alg allowlist), which mitigates algorithm-confusion attacks.
func NewVerifier(jwks JWKS, opts ...VerifierOption) (*Verifier, error) {
	v := &Verifier{keys: make(map[string]JWK, len(jwks.Keys))}
	algSet := make(map[string]struct{})
	for _, k := range jwks.Keys {
		if k.Kid == "" {
			return nil, fmt.Errorf("jwtsigner: JWK without kid in the set")
		}
		if k.Alg == "" {
			return nil, fmt.Errorf("%w: kid %q", ErrJWKWithoutAlg, k.Kid)
		}
		v.keys[k.Kid] = k
		algSet[k.Alg] = struct{}{}
	}
	for a := range algSet {
		v.allowedAlgs = append(v.allowedAlgs, a)
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// Verify validates the signature and the standard claims and returns the parsed
// claims as jwt.MapClaims.
func (v *Verifier) Verify(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	parserOpts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
	}
	parserOpts = append(parserOpts, jwt.WithValidMethods(v.allowedAlgs))
	if v.expectedIssuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.expectedIssuer))
	}
	if v.expectedAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(v.expectedAudience))
	}

	_, err := jwt.ParseWithClaims(tokenString, claims, v.keyfunc, parserOpts...)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *Verifier) keyfunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	jwk, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("jwtsigner: no key for kid %q", kid)
	}
	return jwk.publicKey()
}

// publicKey reconstructs the crypto public key from the JWK parameters.
func (k JWK) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("%w: RSA n: %v", ErrInvalidKey, err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("%w: RSA e: %v", ErrInvalidKey, err)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	case "EC":
		curve, err := curveFromName(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("%w: EC x: %v", ErrInvalidKey, err)
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("%w: EC y: %v", ErrInvalidKey, err)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil
	default:
		return nil, fmt.Errorf("%w: kty %q", ErrInvalidKey, k.Kty)
	}
}

func curveFromName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: curve %q", ErrInvalidKey, name)
	}
}
