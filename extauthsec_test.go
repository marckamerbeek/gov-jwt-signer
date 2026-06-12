// SPDX-License-Identifier: EUPL-1.2

package extauthsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func rsaKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func ecKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

type minimalClaims struct {
	jwt.RegisteredClaims
}

func newTestSigner(t *testing.T, opts ...Option) *Signer {
	t.Helper()
	base := []Option{
		WithIssuer("https://issuer.test"),
		WithSigningKeyPEM(rsaKeyPEM(t)),
	}
	s, err := NewSigner(append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestNewSignerRequiresIssuerAndKey(t *testing.T) {
	if _, err := NewSigner(WithSigningKeyPEM(rsaKeyPEM(t))); err == nil {
		t.Fatal("verwacht fout zonder issuer")
	}
	if _, err := NewSigner(WithIssuer("x")); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("verwacht ErrNoSigningKey, kreeg %v", err)
	}
}

func TestSignSetsHeader(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	tok, err := s.Sign(minimalClaims{jwt.RegisteredClaims{
		Subject:   "sub",
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	}})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Header["typ"] != "JWT" {
		t.Errorf("typ = %v", parsed.Header["typ"])
	}
	if parsed.Header["alg"] != "RS256" {
		t.Errorf("alg = %v", parsed.Header["alg"])
	}
	if parsed.Header["kid"] != s.KeyID() {
		t.Errorf("kid = %v, wil %v", parsed.Header["kid"], s.KeyID())
	}
}

func TestKeyAlgorithmMismatch(t *testing.T) {
	// An EC key with an RSA algorithm must fail.
	_, err := NewSigner(
		WithIssuer("x"),
		WithSigningKeyPEM(ecKeyPEM(t)),
		WithAlgorithm(RS256),
	)
	if !errors.Is(err, ErrKeyAlgorithmMismatch) {
		t.Fatalf("verwacht ErrKeyAlgorithmMismatch, kreeg %v", err)
	}
}

func TestECSignerWorks(t *testing.T) {
	s, err := NewSigner(
		WithIssuer("https://issuer.test"),
		WithSigningKeyPEM(ecKeyPEM(t)),
		WithAlgorithm(ES256),
	)
	if err != nil {
		t.Fatalf("NewSigner EC: %v", err)
	}
	tok, err := s.Sign(minimalClaims{jwt.RegisteredClaims{
		Subject:   "sub",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	v, err := NewVerifier(s.JWKS())
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("verify EC: %v", err)
	}
}

func TestThumbprintStableAndKidUsed(t *testing.T) {
	pemBytes := rsaKeyPEM(t)
	s1, _ := NewSigner(WithIssuer("x"), WithSigningKeyPEM(pemBytes))
	s2, _ := NewSigner(WithIssuer("x"), WithSigningKeyPEM(pemBytes))
	if s1.KeyID() != s2.KeyID() {
		t.Errorf("thumbprint niet stabiel: %s vs %s", s1.KeyID(), s2.KeyID())
	}
	if s1.KeyID() == "" {
		t.Error("kid is leeg")
	}
	// An explicit kid must take precedence.
	s3, _ := NewSigner(WithIssuer("x"), WithSigningKeyPEM(pemBytes), WithKeyID("mijn-kid"))
	if s3.KeyID() != "mijn-kid" {
		t.Errorf("expliciete kid genegeerd: %s", s3.KeyID())
	}
}

func TestVerifierRejectsTamperedToken(t *testing.T) {
	s := newTestSigner(t)
	tok, err := s.Sign(minimalClaims{jwt.RegisteredClaims{
		Subject:   "sub",
		Issuer:    "https://issuer.test",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	v, _ := NewVerifier(s.JWKS())

	// Tamper with the last character of the signature.
	parts := strings.Split(tok, ".")
	sig := []byte(parts[2])
	if sig[len(sig)-1] == 'A' {
		sig[len(sig)-1] = 'B'
	} else {
		sig[len(sig)-1] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)
	if _, err := v.Verify(tampered); err == nil {
		t.Fatal("verwacht fout bij gemanipuleerde handtekening")
	}
}

func TestVerifierEnforcesIssuerAndExpiry(t *testing.T) {
	past := func() time.Time { return time.Now().Add(-time.Hour) }
	s := newTestSigner(t, WithClock(past), WithDefaultTTL(time.Minute))
	tok, _ := s.Sign(minimalClaims{jwt.RegisteredClaims{
		Issuer:    "https://issuer.test",
		Subject:   "sub",
		ExpiresAt: jwt.NewNumericDate(past().Add(time.Minute)), // expired
	}})
	v, _ := NewVerifier(s.JWKS(), WithExpectedIssuer("https://issuer.test"))
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("verwacht fout bij verlopen token")
	}

	// Wrong expected issuer.
	s2 := newTestSigner(t)
	tok2, _ := s2.Sign(minimalClaims{jwt.RegisteredClaims{
		Issuer:    "https://issuer.test",
		Subject:   "sub",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}})
	v2, _ := NewVerifier(s2.JWKS(), WithExpectedIssuer("https://andere.test"))
	if _, err := v2.Verify(tok2); err == nil {
		t.Fatal("verwacht fout bij verkeerde issuer")
	}
}
