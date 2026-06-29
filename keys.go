// SPDX-License-Identifier: EUPL-1.2

package extauthsec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
)

// Algorithm is a JWS signing algorithm as registered in the JOSE namespace
// (RFC 7518, "JSON Web Algorithms").
type Algorithm string

// Supported signing algorithms. All asymmetric: the private key signs and the
// public key (published via JWKS) verifies.
//
// Selection guide:
//   - RS256: RSASSA-PKCS1-v1_5 + SHA-256. Broad interoperability and the baseline
//     of the NL GOV Assurance profile for OAuth 2.0. Safe default for government
//     chains.
//   - PS256: RSASSA-PSS + SHA-256. Cryptographically preferable to RS256
//     (probabilistic padding). Choose this if all verifiers support PSS.
//   - ES256/ES384: ECDSA on P-256/P-384. Smaller keys and signatures.
const (
	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"
	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"
)

func (a Algorithm) isRSA() bool {
	switch a {
	case RS256, RS384, RS512, PS256, PS384, PS512:
		return true
	default:
		return false
	}
}

func (a Algorithm) isEC() bool {
	switch a {
	case ES256, ES384, ES512:
		return true
	default:
		return false
	}
}

func (a Algorithm) supported() bool {
	return a.isRSA() || a.isEC()
}

// parsePrivateKeyPEM parses a PEM-encoded private key. Supported formats are
// PKCS#8 ("PRIVATE KEY"), PKCS#1 ("RSA PRIVATE KEY") and SEC1 ("EC PRIVATE KEY").
func parsePrivateKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: geen PEM-blok gevonden", ErrInvalidKey)
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: PKCS#8: %v", ErrInvalidKey, err)
		}
		return asSigner(key)
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: PKCS#1: %v", ErrInvalidKey, err)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: SEC1: %v", ErrInvalidKey, err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("%w: onbekend PEM-type %q", ErrInvalidKey, block.Type)
	}
}

func asSigner(key any) (crypto.Signer, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: sleuteltype %T wordt niet ondersteund", ErrInvalidKey, key)
	}
}

// JWK is a JSON Web Key (RFC 7517). Only the fields needed to publish a public
// RSA or EC signing key are included.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`

	// RSA parameters (RFC 7518 §6.3).
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC parameters (RFC 7518 §6.2).
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKS is a JSON Web Key Set (RFC 7517 §5). Publish it on an endpoint such as
// /.well-known/jwks.json so that verifiers can validate the signatures.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// publicJWK builds a public JWK from a crypto.Signer, with use=sig, the given
// algorithm and the kid (RFC 7638 thumbprint if empty).
func publicJWK(signer crypto.Signer, alg Algorithm, kid string) (JWK, error) {
	switch pub := signer.Public().(type) {
	case *rsa.PublicKey:
		jwk := JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: string(alg),
			N:   b64u(pub.N.Bytes()),
			E:   b64u(big.NewInt(int64(pub.E)).Bytes()),
		}
		if kid == "" {
			kid = rsaThumbprint(jwk.N, jwk.E)
		}
		jwk.Kid = kid
		return jwk, nil
	case *ecdsa.PublicKey:
		crv, size, err := curveParams(pub.Curve)
		if err != nil {
			return JWK{}, err
		}
		jwk := JWK{
			Kty: "EC",
			Use: "sig",
			Alg: string(alg),
			Crv: crv,
			X:   b64u(leftPad(pub.X.Bytes(), size)),
			Y:   b64u(leftPad(pub.Y.Bytes(), size)),
		}
		if kid == "" {
			kid = ecThumbprint(jwk.Crv, jwk.X, jwk.Y)
		}
		jwk.Kid = kid
		return jwk, nil
	default:
		return JWK{}, fmt.Errorf("%w: public key %T", ErrInvalidKey, pub)
	}
}

func curveParams(c elliptic.Curve) (name string, byteSize int, err error) {
	switch c {
	case elliptic.P256():
		return "P-256", 32, nil
	case elliptic.P384():
		return "P-384", 48, nil
	case elliptic.P521():
		return "P-521", 66, nil
	default:
		return "", 0, fmt.Errorf("%w: non-supported curve", ErrInvalidKey)
	}
}

// rsaThumbprint computes the RFC 7638 JWK thumbprint for an RSA key.
// The canonical JSON contains only the required members in lexicographic
// order: {"e":...,"kty":"RSA","n":...}.
func rsaThumbprint(n, e string) string {
	canonical := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)
	sum := sha256.Sum256([]byte(canonical))
	return b64u(sum[:])
}

// ecThumbprint computes the RFC 7638 JWK thumbprint for an EC key:
// {"crv":...,"kty":"EC","x":...,"y":...}.
func ecThumbprint(crv, x, y string) string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return b64u(sum[:])
}

// b64u encodes bytes as base64url without padding (RFC 7515 §2 "Base64url Encoding").
func b64u(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// leftPad left-pads a big-endian integer with zeros to the fixed length that JWK
// requires for EC coordinates (RFC 7518 §6.2.1.2).
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// MarshalJSON guarantees a stable, non-nil keys array in the JWKS output.
func (s JWKS) MarshalJSON() ([]byte, error) {
	type alias JWKS
	a := alias(s)
	if a.Keys == nil {
		a.Keys = []JWK{}
	}
	return json.Marshal(a)
}
