// SPDX-License-Identifier: EUPL-1.2

package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"
	"time"

	jwtsigner "github.com/marckamerbeek/gov-jwt-signer"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/claims"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/token"
)

var (
	jtiPattern = regexp.MustCompile(`"jti":"[^"]*"`)
	kidPattern = regexp.MustCompile(`"kid":"[^"]*"`)
)

// goldenService builds a Service with a fixed clock, so payloads are
// deterministic apart from jti.
func goldenService(t *testing.T) *token.Service {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	signer, err := jwtsigner.NewSigner(
		jwtsigner.WithIssuer(testIssuer),
		jwtsigner.WithSigningKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		jwtsigner.WithClock(func() time.Time { return time.Unix(1_700_000_100, 0) }),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	svc, err := token.NewService(signer)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	return svc
}

// rawPart base64url-decodes segment i of a compact JWS and masks the random
// jti and kid values.
func rawPart(t *testing.T, tok string, i int) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[i])
	if err != nil {
		t.Fatal(err)
	}
	s := jtiPattern.ReplaceAllString(string(b), `"jti":"X"`)
	return kidPattern.ReplaceAllString(s, `"kid":"X"`)
}

// TestExistingVariantsGolden pins the header and payload bytes of the
// pre-access-token variants (as produced by v0.1.1), so adding the RFC 9068
// variant cannot change them. jti and kid are random per run and masked.
func TestExistingVariantsGolden(t *testing.T) {
	svc := goldenService(t)
	cases := []struct {
		name    string
		issue   func() (string, error)
		payload string
	}{
		{
			name: "eidas",
			issue: func() (string, error) {
				return svc.IssueEIDAS(token.EIDASRequest{CommonRequest: common(), LoA: claims.LoAHigh,
					Person: claims.EIDAS{PersonIdentifier: "NL/NL/123", FamilyName: "De Vries", GivenName: "Anna", DateOfBirth: "1990-05-17"}})
			},
			payload: `{"acr":"http://eidas.europa.eu/LoA/high","amr":["pwd","mfa"],"aud":["urn:service:target"],"auth_time":1700000000,"eidas":{"person_identifier":"NL/NL/123","family_name":"De Vries","given_name":"Anna","date_of_birth":"1990-05-17"},"exp":1700000400,"iat":1700000100,"iss":"https://signer.example.org","jti":"X","nbf":1700000100,"sub":"subject-123","token_type":"eidas"}`,
		},
		{
			name: "digid",
			issue: func() (string, error) {
				return svc.IssueDigiD(token.DigiDRequest{CommonRequest: common(),
					Claims: claims.DigiD{BSN: "123456782", AssuranceLevel: claims.DigiDSubstantieel}})
			},
			payload: `{"acr":"http://eidas.europa.eu/LoA/substantial","amr":["pwd","mfa"],"aud":["urn:service:target"],"auth_time":1700000000,"digid":{"bsn":"123456782","betrouwbaarheidsniveau":"substantieel"},"exp":1700000400,"iat":1700000100,"iss":"https://signer.example.org","jti":"X","nbf":1700000100,"sub":"subject-123","token_type":"digid"}`,
		},
		{
			name: "eherkenning",
			issue: func() (string, error) {
				return svc.IssueEHerkenning(token.EHerkenningRequest{CommonRequest: common(),
					Claims: claims.EHerkenning{KvK: "12345678", ActingSubjectID: "act-1", AssuranceClass: claims.EHLoA4}})
			},
			payload: `{"acr":"http://eidas.europa.eu/LoA/high","amr":["pwd","mfa"],"aud":["urn:service:target"],"auth_time":1700000000,"eherkenning":{"kvk_number":"12345678","acting_subject_id":"act-1","assurance_class":"urn:etoegang:core:assurance-class:loa4"},"exp":1700000400,"iat":1700000100,"iss":"https://signer.example.org","jti":"X","nbf":1700000100,"sub":"subject-123","token_type":"eherkenning"}`,
		},
		{
			name: "custom",
			issue: func() (string, error) {
				return svc.IssueCustom(token.CustomRequest{CommonRequest: common(), Type: "acme-portal", ClaimsKey: "acme-portal",
					ACR: "urn:example:loa:internal", Claims: acmeClaims{EmployeeID: "EMP-007", Roles: []string{"admin"}}})
			},
			payload: `{"acme-portal":{"employee_id":"EMP-007","roles":["admin"]},"acr":"urn:example:loa:internal","amr":["pwd","mfa"],"aud":["urn:service:target"],"auth_time":1700000000,"exp":1700000400,"iat":1700000100,"iss":"https://signer.example.org","jti":"X","nbf":1700000100,"sub":"subject-123","token_type":"acme-portal"}`,
		},
	}
	const wantHeader = `{"alg":"RS256","kid":"X","typ":"JWT"}`
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := tc.issue()
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			if got := rawPart(t, tok, 0); got != wantHeader {
				t.Errorf("header changed:\n got  %s\n want %s", got, wantHeader)
			}
			if got := rawPart(t, tok, 1); got != tc.payload {
				t.Errorf("payload changed:\n got  %s\n want %s", got, tc.payload)
			}
		})
	}
}
