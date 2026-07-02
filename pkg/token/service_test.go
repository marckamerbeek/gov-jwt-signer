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

	jwtsigner "github.com/marckamerbeek/gov-jwt-signer"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/claims"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/token"
)

const testIssuer = "https://signer.example.org"

// newTestService builds a Signer with a fresh RSA key and a Service around it,
// plus a Verifier based on the corresponding JWKS.
func newTestService(t *testing.T) (*token.Service, *jwtsigner.Verifier) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	signer, err := jwtsigner.NewSigner(
		jwtsigner.WithIssuer(testIssuer),
		jwtsigner.WithSigningKeyPEM(pemBytes),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	svc, err := token.NewService(signer)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	verifier, err := jwtsigner.NewVerifier(
		signer.JWKS(),
		jwtsigner.WithExpectedIssuer(testIssuer),
		jwtsigner.WithExpectedAudience("urn:service:target"),
	)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	return svc, verifier
}

func common() token.CommonRequest {
	return token.CommonRequest{
		Subject:  "subject-123",
		Audience: []string{"urn:service:target"},
		AMR:      []string{"pwd", "mfa"},
		AuthTime: time.Unix(1_700_000_000, 0),
	}
}

// assertBaseClaims checks the shared base that every variant has identically.
func assertBaseClaims(t *testing.T, c map[string]any, wantType string) {
	t.Helper()
	if c["iss"] != testIssuer {
		t.Errorf("iss = %v, expected %v", c["iss"], testIssuer)
	}
	if c["sub"] != "subject-123" {
		t.Errorf("sub = %v", c["sub"])
	}
	if c["token_type"] != wantType {
		t.Errorf("token_type = %v, expected %v", c["token_type"], wantType)
	}
	for _, claim := range []string{"exp", "nbf", "iat", "jti", "aud"} {
		if _, ok := c[claim]; !ok {
			t.Errorf("required claim %q is missing", claim)
		}
	}
}

// acmeClaims is a consumer-defined payload used to exercise IssueCustom.
type acmeClaims struct {
	EmployeeID string   `json:"employee_id"`
	Roles      []string `json:"roles,omitempty"`
}

func (p acmeClaims) Validate() error {
	if p.EmployeeID == "" {
		return errMissingEmployeeID
	}
	return nil
}

var errMissingEmployeeID = errors.New("employee_id is missing")

func TestIssueCustom(t *testing.T) {
	svc, verifier := newTestService(t)
	tok, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: common(),
		Type:          "acme-portal",
		ClaimsKey:     "acme-portal",
		ACR:           "urn:example:loa:internal",
		Claims: acmeClaims{
			EmployeeID: "EMP-007",
			Roles:      []string{"admin"},
		},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	assertBaseClaims(t, c, "acme-portal")
	if c["acr"] != "urn:example:loa:internal" {
		t.Errorf("acr = %v, expected custom value", c["acr"])
	}
	obj, ok := c["acme-portal"].(map[string]any)
	if !ok {
		t.Fatalf("acme-portal object is missing or has wrong type: %T", c["acme-portal"])
	}
	if obj["employee_id"] != "EMP-007" {
		t.Errorf("employee_id = %v", obj["employee_id"])
	}
	if _, ok := c["eidas"]; ok {
		t.Error("eidas object should be absent")
	}
}

func TestIssueCustomValidations(t *testing.T) {
	svc, _ := newTestService(t)

	// Missing Type.
	if _, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: common(), ClaimsKey: "x", Claims: acmeClaims{EmployeeID: "1"},
	}); !errors.Is(err, token.ErrMissingTokenType) {
		t.Fatalf("expected ErrMissingTokenType, got %v", err)
	}

	// Claims without ClaimsKey.
	if _, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: common(), Type: "x", Claims: acmeClaims{EmployeeID: "1"},
	}); !errors.Is(err, token.ErrMissingClaimsKey) {
		t.Fatalf("expected ErrMissingClaimsKey, got %v", err)
	}

	// ClaimsKey collides with a reserved claim.
	if _, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: common(), Type: "x", ClaimsKey: "iss", Claims: acmeClaims{EmployeeID: "1"},
	}); !errors.Is(err, token.ErrReservedClaimsKey) {
		t.Fatalf("expected ErrReservedClaimsKey for 'iss', got %v", err)
	}

	// ClaimsKey collides with the token-type claim.
	if _, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: common(), Type: "x", ClaimsKey: "token_type", Claims: acmeClaims{EmployeeID: "1"},
	}); !errors.Is(err, token.ErrReservedClaimsKey) {
		t.Fatalf("expected ErrReservedClaimsKey for token-type claim, got %v", err)
	}

	// Payload Validate() is honoured.
	if _, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: common(), Type: "x", ClaimsKey: "acme-portal", Claims: acmeClaims{},
	}); !errors.Is(err, errMissingEmployeeID) {
		t.Fatalf("expected validation error from payload, got %v", err)
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
		t.Fatalf("issue: %v", err)
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	assertBaseClaims(t, c, "eidas")
	if c["acr"] != string(claims.LoAHigh) {
		t.Errorf("acr = %v, expected %v", c["acr"], claims.LoAHigh)
	}
}

func TestIssueEIDASRejectsInvalidLoA(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.IssueEIDAS(token.EIDASRequest{
		CommonRequest: common(),
		LoA:           "http://eidas.europa.eu/LoA/nonsense",
		Person: claims.EIDAS{
			PersonIdentifier: "NL/NL/123", FamilyName: "X", GivenName: "Y", DateOfBirth: "1990-01-01",
		},
	})
	if !errors.Is(err, claims.ErrInvalidAssuranceLevel) {
		t.Fatalf("expected ErrInvalidAssuranceLevel, got %v", err)
	}
}

func TestIssueDigiD(t *testing.T) {
	svc, verifier := newTestService(t)
	tok, err := svc.IssueDigiD(token.DigiDRequest{
		CommonRequest: common(),
		Claims: claims.DigiD{
			BSN:            "123456782",
			AssuranceLevel: claims.DigiDSubstantieel,
		},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	assertBaseClaims(t, c, "digid")
	if c["acr"] != string(claims.LoASubstantial) {
		t.Errorf("acr = %v, expected derived substantial", c["acr"])
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
		t.Fatalf("issue: %v", err)
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	assertBaseClaims(t, c, "eherkenning")
	if c["acr"] != string(claims.LoAHigh) {
		t.Errorf("acr = %v, expected derived high", c["acr"])
	}
}

func TestIssueRequiresSubject(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: token.CommonRequest{Audience: []string{"urn:service:target"}},
		Type:          "acme-portal",
		ClaimsKey:     "acme-portal",
		Claims:        acmeClaims{EmployeeID: "EMP-1"},
	})
	if !errors.Is(err, claims.ErrMissingSubject) {
		t.Fatalf("expected ErrMissingSubject, got %v", err)
	}
}

func TestIssueRequiresAudience(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: token.CommonRequest{Subject: "subject-123"},
		Type:          "acme-portal",
		ClaimsKey:     "acme-portal",
		Claims:        acmeClaims{EmployeeID: "EMP-1"},
	})
	if !errors.Is(err, claims.ErrMissingAudience) {
		t.Fatalf("expected ErrMissingAudience, got %v", err)
	}
}

func TestIssueValidatesVariantClaims(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.IssueDigiD(token.DigiDRequest{
		CommonRequest: common(),
		Claims:        claims.DigiD{AssuranceLevel: claims.DigiDHoog}, // no BSN/pseudonym
	})
	if !errors.Is(err, claims.ErrMissingDigiDIdentifier) {
		t.Fatalf("expected ErrMissingDigiDIdentifier, got %v", err)
	}
}

// TestVariantsShareIdenticalBase confirms that two different variants produce the
// same set of base claims and the same header; only the variant part differs.
func TestVariantsShareIdenticalBase(t *testing.T) {
	svc, verifier := newTestService(t)

	mtok, err := svc.IssueCustom(token.CustomRequest{
		CommonRequest: common(),
		Type:          "acme-portal",
		ClaimsKey:     "acme-portal",
		Claims:        acmeClaims{EmployeeID: "EMP-1"},
	})
	if err != nil {
		t.Fatalf("custom issue: %v", err)
	}
	dtok, err := svc.IssueDigiD(token.DigiDRequest{
		CommonRequest: common(),
		Claims:        claims.DigiD{BSN: "123456782", AssuranceLevel: claims.DigiDHoog},
	})
	if err != nil {
		t.Fatalf("digid issue: %v", err)
	}

	mc, err := verifier.Verify(mtok)
	if err != nil {
		t.Fatalf("custom verify: %v", err)
	}
	dc, err := verifier.Verify(dtok)
	if err != nil {
		t.Fatalf("digid verify: %v", err)
	}

	for _, k := range []string{"iss", "sub", "aud"} {
		if !equalJSON(mc[k], dc[k]) {
			t.Errorf("base claim %q differs between variants: %v vs %v", k, mc[k], dc[k])
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
