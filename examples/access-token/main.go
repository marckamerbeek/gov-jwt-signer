// SPDX-License-Identifier: EUPL-1.2

// Command access-token demonstrates issuing an RFC 9068 JWT access token
// (typ "at+jwt") with top-level client_id, scope, roles and OIDC identity
// claims, optionally dual-emitting a nested variant object, and verifying it.
//
// Run:
//
//	go run ./examples/access-token
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	jwtsigner "github.com/marckamerbeek/gov-jwt-signer"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/claims"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/token"
)

func main() {
	// In production the key comes from Vault/HSM; here we generate one for the demo.
	keyPEM := mustGenerateRSAKeyPEM(2048)

	signer, err := jwtsigner.NewSigner(
		jwtsigner.WithIssuer("https://signer.example.org"),
		jwtsigner.WithAlgorithm(jwtsigner.RS256),
		jwtsigner.WithSigningKeyPEM(keyPEM),
		jwtsigner.WithDefaultTTL(5*time.Minute),
		// RFC 9068 §2.1: the header typ of a JWT access token is "at+jwt".
		jwtsigner.WithHeaderTyp("at+jwt"),
	)
	if err != nil {
		log.Fatalf("signer: %v", err)
	}

	svc, err := token.NewService(signer)
	if err != nil {
		log.Fatalf("service: %v", err)
	}

	at, err := svc.IssueAccessToken(token.AccessTokenRequest{
		CommonRequest: token.CommonRequest{
			Subject:  "emp-00421",
			Audience: []string{"https://api.example.org"},
			AMR:      []string{"pwd", "mfa"},
			AuthTime: time.Now().Add(-2 * time.Minute),
		},
		ClientID:          "portal-frontend",
		Scope:             "cases:read cases:write",
		Roles:             []string{"case-handler"},
		Name:              "Jane Doe",
		PreferredUsername: "j.doe",
		ACR:               string(claims.LoASubstantial),
		// Optional: nest a legacy payload during a migration window.
		ClaimsKey: "acme-portal",
		Claims:    acmeClaims{EmployeeID: "00421", Department: "Platform Engineering"},
	})
	if err != nil {
		log.Fatalf("access token: %v", err)
	}
	fmt.Printf("[access token]\n%s\n\n", at)
	fmt.Printf("header:  %s\n", mustDecodeSegment(at, 0))
	fmt.Printf("payload: %s\n", mustDecodeSegment(at, 1))

	// Verify the issued token.
	verifier, err := jwtsigner.NewVerifier(signer.JWKS(),
		jwtsigner.WithExpectedIssuer("https://signer.example.org"),
		jwtsigner.WithExpectedAudience("https://api.example.org"),
	)
	if err != nil {
		log.Fatalf("verifier: %v", err)
	}
	verified, err := verifier.Verify(at)
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Printf("\naccess token verified. client_id=%v, scope=%v, roles=%v\n",
		verified["client_id"], verified["scope"], verified["roles"])
}

// acmeClaims is an example of a consumer-defined payload nested alongside the
// access-token claims. It lives in the application, not in the library.
type acmeClaims struct {
	EmployeeID string `json:"employee_id"`
	Department string `json:"department,omitempty"`
}

func (p acmeClaims) Validate() error {
	if p.EmployeeID == "" {
		return fmt.Errorf("employee_id is missing")
	}
	return nil
}

// mustDecodeSegment returns segment i of a compact JWS as indented JSON.
func mustDecodeSegment(tok string, i int) string {
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[i])
	if err != nil {
		log.Fatalf("decode segment: %v", err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		log.Fatalf("parse segment: %v", err)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatalf("format segment: %v", err)
	}
	return string(out)
}

func mustGenerateRSAKeyPEM(bits int) []byte {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
