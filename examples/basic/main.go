// SPDX-License-Identifier: EUPL-1.2

// Command basic demonstrates issuing the three built-in token variants plus a
// caller-defined custom variant, publishing the JWKS and verifying an issued
// token.
//
// Run:
//
//	go run ./examples/basic
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	extauthsec "github.com/marckamerbeek/gov-jwt-signer"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/claims"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/token"
)

func main() {
	// In production the key comes from Vault/HSM; here we generate one for the demo.
	keyPEM := mustGenerateRSAKeyPEM(2048)

	signer, err := extauthsec.NewSigner(
		extauthsec.WithIssuer("https://extauth.example.org"),
		extauthsec.WithAlgorithm(extauthsec.RS256),
		extauthsec.WithSigningKeyPEM(keyPEM),
		extauthsec.WithDefaultTTL(5*time.Minute),
	)
	if err != nil {
		log.Fatalf("signer: %v", err)
	}

	svc, err := token.NewService(signer)
	if err != nil {
		log.Fatalf("service: %v", err)
	}

	fmt.Printf("kid: %s\nalg: %s\n\n", signer.KeyID(), signer.Algorithm())

	// 1. Custom variant: a caller-defined token type. The payload is an ordinary
	// struct owned by the consuming application; optionally it implements
	// Validate() to be checked before signing.
	mp, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: token.CommonRequest{Subject: "emp-00421", Audience: []string{"acme-portal-api"}},
		Type:          "acme-portal",
		ClaimsKey:     "acme-portal",
		Claims: acmeClaims{
			EmployeeID:        "00421",
			PreferredUsername: "j.doe",
			GivenName:         "Jane",
			FamilyName:        "Doe",
			Department:        "Platform Engineering",
			Roles:             []string{"platform-admin", "viewer"},
		},
	})
	must("custom (acme-portal)", mp, err)

	// 2. eIDAS
	eid, err := svc.IssueEIDAS(token.EIDASRequest{
		CommonRequest: token.CommonRequest{Subject: "NL/BE/12345", Audience: []string{"grensoverschrijdende-dienst"}},
		LoA:           claims.LoAHigh,
		Person: claims.EIDAS{
			PersonIdentifier: "NL/BE/12345",
			FamilyName:       "Janssen",
			GivenName:        "Pieter",
			DateOfBirth:      "1985-03-21",
			Nationality:      "NL",
		},
	})
	must("eidas", eid, err)

	// 3. DigiD
	dig, err := svc.IssueDigiD(token.DigiDRequest{
		CommonRequest: token.CommonRequest{Subject: "burger-pseudonym-9f2", Audience: []string{"burgerportaal"}},
		Claims: claims.DigiD{
			Pseudonym:              "9f2c7b1e-...",
			Betrouwbaarheidsniveau: claims.DigiDSubstantieel,
		},
	})
	must("digid", dig, err)

	// 4. eHerkenning
	eh, err := svc.IssueEHerkenning(token.EHerkenningRequest{
		CommonRequest: token.CommonRequest{Subject: "kvk-12345678", Audience: []string{"zakelijk-loket"}},
		Claims: claims.EHerkenning{
			KvK:             "12345678",
			ActingSubjectID: "urn:etoegang:1.9:id:...",
			ServiceID:       "urn:etoegang:DV:00000001234567890000:services:0001",
			AssuranceClass:  claims.EHLoA3,
		},
	})
	must("eherkenning", eh, err)

	// Publish the JWKS (to be served at /.well-known/jwks.json).
	jwks, err := signer.JWKSJSON()
	if err != nil {
		log.Fatalf("jwks: %v", err)
	}
	fmt.Printf("\nJWKS:\n%s\n", jwks)

	// Verify an issued token.
	verifier, err := extauthsec.NewVerifier(signer.JWKS(),
		extauthsec.WithExpectedIssuer("https://extauth.example.org"),
		extauthsec.WithExpectedAudience("grensoverschrijdende-dienst"),
	)
	if err != nil {
		log.Fatalf("verifier: %v", err)
	}
	verified, err := verifier.Verify(eid)
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Printf("\neIDAS-token geverifieerd. acr=%v, type=%v\n",
		verified["acr"], verified[claims.DefaultTokenTypeClaim])
}

// acmeClaims is an example of a consumer-defined payload for a custom token
// variant. It lives in the application, not in the library. The optional
// Validate method is invoked by IssueCustom before signing.
type acmeClaims struct {
	EmployeeID        string   `json:"employee_id"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	FamilyName        string   `json:"family_name,omitempty"`
	Department        string   `json:"department,omitempty"`
	Roles             []string `json:"roles,omitempty"`
}

func (p acmeClaims) Validate() error {
	if p.EmployeeID == "" {
		return fmt.Errorf("employee_id ontbreekt")
	}
	return nil
}

func must(name, tok string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", name, err)
	}
	fmt.Printf("[%s]\n%s\n\n", name, tok)
}

func mustGenerateRSAKeyPEM(bits int) []byte {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatalf("genereer sleutel: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("marshal sleutel: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
