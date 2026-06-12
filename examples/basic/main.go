// SPDX-License-Identifier: EUPL-1.2

// Command basic demonstrates issuing all four token variants,
// publishing the JWKS and verifying an issued token.
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

	extauthsec "github.com/cjib/gloo-gateway-extauth-sec"
	"github.com/cjib/gloo-gateway-extauth-sec/pkg/claims"
	"github.com/cjib/gloo-gateway-extauth-sec/pkg/token"
)

func main() {
	// In production the key comes from Vault/HSM; here we generate one for the demo.
	keyPEM := mustGenerateRSAKeyPEM(2048)

	signer, err := extauthsec.NewSigner(
		extauthsec.WithIssuer("https://extauth.cjib.nl"),
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

	// 1. Medewerkersportaal
	mp, err := svc.IssueMedewerkersportaal(token.MedewerkersportaalRequest{
		CommonRequest: token.CommonRequest{Subject: "emp-00421", Audience: []string{"medewerkersportaal-api"}},
		Claims: claims.Medewerkersportaal{
			EmployeeID:        "00421",
			PreferredUsername: "m.kamerbeek",
			GivenName:         "Marc",
			FamilyName:        "Kamerbeek",
			Department:        "Platform Engineering",
			Organisation:      "00000001823288444000",
			Roles:             []string{"platform-admin", "viewer"},
		},
	})
	must("medewerkersportaal", mp, err)

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
		CommonRequest: token.CommonRequest{Subject: "burger-pseudonym-9f2", Audience: []string{"mijn-cjib"}},
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
		extauthsec.WithExpectedIssuer("https://extauth.cjib.nl"),
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
		verified["acr"], verified[claims.TokenTypeClaim])
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
