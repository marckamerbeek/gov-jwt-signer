// SPDX-License-Identifier: EUPL-1.2

package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	extauthsec "github.com/cjib/gloo-gateway-extauth-sec"
	"github.com/cjib/gloo-gateway-extauth-sec/pkg/claims"
	"github.com/cjib/gloo-gateway-extauth-sec/pkg/token"
)

const testIssuer = "https://extauth.cjib.nl"

// newTestService builds a Signer with a fresh RSA key and a Service around it,
// plus a Verifier based on the corresponding JWKS.
func newTestService(t *testing.T) (*token.Service, *extauthsec.Verifier) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("sleutel genereren: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("sleutel marshallen: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	signer, err := extauthsec.NewSigner(
		extauthsec.WithIssuer(testIssuer),
		extauthsec.WithSigningKeyPEM(pemBytes),
	)
	if err != nil {
		t.Fatalf("signer maken: %v", err)
	}
	svc, err := token.NewService(signer)
	if err != nil {
		t.Fatalf("service maken: %v", err)
	}
	verifier, err := extauthsec.NewVerifier(
		signer.JWKS(),
		extauthsec.WithExpectedIssuer(testIssuer),
		extauthsec.WithExpectedAudience("urn:dienst:doel"),
	)
	if err != nil {
		t.Fatalf("verifier maken: %v", err)
	}
	return svc, verifier
}

func common() token.CommonRequest {
	return token.CommonRequest{
		Subject:  "subject-123",
		Audience: []string{"urn:dienst:doel"},
		AMR:      []string{"pwd", "mfa"},
		AuthTime: time.Unix(1_700_000_000, 0),
	}
}

// assertBaseClaims checks the shared base that every variant has identically.
func assertBaseClaims(t *testing.T, c map[string]any, wantType string) {
	t.Helper()
	if c["iss"] != testIssuer {
		t.Errorf("iss = %v, verwacht %v", c["iss"], testIssuer)
	}
	if c["sub"] != "subject-123" {
		t.Errorf("sub = %v", c["sub"])
	}
	if c["cjib_token_type"] != wantType {
		t.Errorf("cjib_token_type = %v, verwacht %v", c["cjib_token_type"], wantType)
	}
	for _, claim := range []string{"exp", "nbf", "iat", "jti", "aud"} {
		if _, ok := c[claim]; !ok {
			t.Errorf("verplichte claim %q ontbreekt", claim)
		}
	}
}

func TestIssueMedewerkersportaal(t *testing.T) {
	svc, verifier := newTestService(t)
	tok, err := svc.IssueMedewerkersportaal(token.MedewerkersportaalRequest{
		CommonRequest: common(),
		Claims: claims.Medewerkersportaal{
			EmployeeID: "EMP-007",
			Roles:      []string{"beheerder"},
		},
	})
	if err != nil {
		t.Fatalf("uitgifte: %v", err)
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verificatie: %v", err)
	}
	assertBaseClaims(t, c, "medewerkersportaal")
	if _, ok := c["medewerkersportaal"]; !ok {
		t.Error("medewerkersportaal-object ontbreekt")
	}
	if _, ok := c["eidas"]; ok {
		t.Error("eidas-object zou afwezig moeten zijn")
	}
}

func TestIssueEIDAS(t *testing.T) {
	svc, verifier := newTestService(t)
	tok, err := svc.IssueEIDAS(token.EIDASRequest{
		CommonRequest: common(),
		LoA:           claims.LoAHigh,
		Person: claims.EIDAS{
			PersonIdentifier: "NL/NL/123",
			FamilyName:       "De Vries",
			GivenName:        "Anna",
			DateOfBirth:      "1990-05-17",
		},
	})
	if err != nil {
		t.Fatalf("uitgifte: %v", err)
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verificatie: %v", err)
	}
	assertBaseClaims(t, c, "eidas")
	if c["acr"] != string(claims.LoAHigh) {
		t.Errorf("acr = %v, verwacht %v", c["acr"], claims.LoAHigh)
	}
}

func TestIssueEIDASRejectsInvalidLoA(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.IssueEIDAS(token.EIDASRequest{
		CommonRequest: common(),
		LoA:           "http://eidas.europa.eu/LoA/onzin",
		Person: claims.EIDAS{
			PersonIdentifier: "NL/NL/123", FamilyName: "X", GivenName: "Y", DateOfBirth: "1990-01-01",
		},
	})
	if !errors.Is(err, claims.ErrInvalidAssuranceLevel) {
		t.Fatalf("verwacht ErrInvalidAssuranceLevel, kreeg %v", err)
	}
}

func TestIssueDigiD(t *testing.T) {
	svc, verifier := newTestService(t)
	tok, err := svc.IssueDigiD(token.DigiDRequest{
		CommonRequest: common(),
		Claims: claims.DigiD{
			BSN:                    "123456782",
			Betrouwbaarheidsniveau: claims.DigiDSubstantieel,
		},
	})
	if err != nil {
		t.Fatalf("uitgifte: %v", err)
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verificatie: %v", err)
	}
	assertBaseClaims(t, c, "digid")
	if c["acr"] != string(claims.LoASubstantial) {
		t.Errorf("acr = %v, verwacht afgeleid substantial", c["acr"])
	}
}

func TestIssueEHerkenning(t *testing.T) {
	svc, verifier := newTestService(t)
	tok, err := svc.IssueEHerkenning(token.EHerkenningRequest{
		CommonRequest: common(),
		Claims: claims.EHerkenning{
			KvK:             "12345678",
			ActingSubjectID: "act-1",
			AssuranceClass:  claims.EHLoA4,
		},
	})
	if err != nil {
		t.Fatalf("uitgifte: %v", err)
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verificatie: %v", err)
	}
	assertBaseClaims(t, c, "eherkenning")
	if c["acr"] != string(claims.LoAHigh) {
		t.Errorf("acr = %v, verwacht afgeleid high", c["acr"])
	}
}

func TestIssueRequiresSubject(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.IssueMedewerkersportaal(token.MedewerkersportaalRequest{
		Claims: claims.Medewerkersportaal{EmployeeID: "EMP-1"},
	})
	if !errors.Is(err, claims.ErrMissingSubject) {
		t.Fatalf("verwacht ErrMissingSubject, kreeg %v", err)
	}
}

func TestIssueValidatesVariantClaims(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.IssueDigiD(token.DigiDRequest{
		CommonRequest: common(),
		Claims:        claims.DigiD{Betrouwbaarheidsniveau: claims.DigiDHoog}, // no BSN/pseudonym
	})
	if !errors.Is(err, claims.ErrMissingDigiDIdentifier) {
		t.Fatalf("verwacht ErrMissingDigiDIdentifier, kreeg %v", err)
	}
}

// TestVariantsShareIdenticalBase confirms that two different variants produce the
// same set of base claims and the same header; only the variant part differs.
func TestVariantsShareIdenticalBase(t *testing.T) {
	svc, verifier := newTestService(t)

	mtok, err := svc.IssueMedewerkersportaal(token.MedewerkersportaalRequest{
		CommonRequest: common(),
		Claims:        claims.Medewerkersportaal{EmployeeID: "EMP-1"},
	})
	if err != nil {
		t.Fatalf("medewerker uitgifte: %v", err)
	}
	dtok, err := svc.IssueDigiD(token.DigiDRequest{
		CommonRequest: common(),
		Claims:        claims.DigiD{BSN: "123456782", Betrouwbaarheidsniveau: claims.DigiDHoog},
	})
	if err != nil {
		t.Fatalf("digid uitgifte: %v", err)
	}

	mc, err := verifier.Verify(mtok)
	if err != nil {
		t.Fatalf("medewerker verificatie: %v", err)
	}
	dc, err := verifier.Verify(dtok)
	if err != nil {
		t.Fatalf("digid verificatie: %v", err)
	}

	for _, k := range []string{"iss", "sub", "aud"} {
		if !equalJSON(mc[k], dc[k]) {
			t.Errorf("basisclaim %q verschilt tussen varianten: %v vs %v", k, mc[k], dc[k])
		}
	}
}

func equalJSON(a, b any) bool {
	as, aok := a.([]any)
	bs, bok := b.([]any)
	if aok && bok {
		if len(as) != len(bs) {
			return false
		}
		for i := range as {
			if as[i] != bs[i] {
				return false
			}
		}
		return true
	}
	return a == b
}
