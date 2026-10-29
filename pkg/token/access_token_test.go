// SPDX-License-Identifier: EUPL-1.2

package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"

	jwtsigner "github.com/marckamerbeek/gov-jwt-signer"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/token"
)

// newAccessTokenService builds a Signer configured for RFC 9068 (typ at+jwt),
// a Service around it and a Verifier based on the corresponding JWKS.
func newAccessTokenService(t *testing.T) (*token.Service, *jwtsigner.Verifier) {
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
		jwtsigner.WithHeaderTyp("at+jwt"),
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

// mwpClaims is a consumer-defined payload used to exercise dual-emit.
type mwpClaims struct {
	Organisation string `json:"organisation"`
}

func TestIssueAccessToken(t *testing.T) {
	svc, verifier := newAccessTokenService(t)
	tok, err := svc.IssueAccessToken(token.AccessTokenRequest{
		CommonRequest:     common(),
		ClientID:          "client-abc",
		Scope:             "read write",
		Roles:             []string{"admin", "viewer"},
		Name:              "Jane Doe",
		Email:             "jane@example.org",
		PreferredUsername: "j.doe",
		ACR:               "urn:example:loa:substantial",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var header map[string]any
	if err := json.Unmarshal([]byte(rawPart(t, tok, 0)), &header); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if header["typ"] != "at+jwt" {
		t.Errorf("typ = %v, expected at+jwt", header["typ"])
	}

	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, claim := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} {
		if _, ok := c[claim]; !ok {
			t.Errorf("required claim %q is missing", claim)
		}
	}
	want := map[string]any{
		"iss":                testIssuer,
		"sub":                "subject-123",
		"client_id":          "client-abc",
		"scope":              "read write",
		"name":               "Jane Doe",
		"email":              "jane@example.org",
		"preferred_username": "j.doe",
		"acr":                "urn:example:loa:substantial",
		"auth_time":          float64(1_700_000_000),
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("%s = %v, expected %v", k, c[k], v)
		}
	}
	if !equalJSON(c["roles"], []any{"admin", "viewer"}) {
		t.Errorf("roles = %v", c["roles"])
	}
	if !equalJSON(c["amr"], []any{"pwd", "mfa"}) {
		t.Errorf("amr = %v", c["amr"])
	}
	if _, ok := c["token_type"]; ok {
		t.Errorf("token_type must be absent, got %v", c["token_type"])
	}
}

func TestIssueAccessTokenOmitsEmptyClaims(t *testing.T) {
	svc, verifier := newAccessTokenService(t)
	for name, roles := range map[string][]string{"nil roles": nil, "empty roles": {}} {
		t.Run(name, func(t *testing.T) {
			tok, err := svc.IssueAccessToken(token.AccessTokenRequest{
				CommonRequest: token.CommonRequest{
					Subject:  "subject-123",
					Audience: []string{"urn:service:target"},
				},
				ClientID: "client-abc",
				Roles:    roles,
			})
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			c, err := verifier.Verify(tok)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			for _, k := range []string{
				"scope", "roles", "name", "email", "preferred_username",
				"acr", "auth_time", "amr", "token_type",
			} {
				if v, ok := c[k]; ok {
					t.Errorf("claim %q should be absent, got %v", k, v)
				}
			}
		})
	}
}

func TestIssueAccessTokenRequiresClientID(t *testing.T) {
	svc, _ := newAccessTokenService(t)
	_, err := svc.IssueAccessToken(token.AccessTokenRequest{CommonRequest: common()})
	if !errors.Is(err, token.ErrMissingClientID) {
		t.Fatalf("expected ErrMissingClientID, got %v", err)
	}
}

func TestIssueAccessTokenDualEmit(t *testing.T) {
	svc, verifier := newAccessTokenService(t)
	tok, err := svc.IssueAccessToken(token.AccessTokenRequest{
		CommonRequest: common(),
		ClientID:      "client-abc",
		Roles:         []string{"admin"},
		ClaimsKey:     "mwp",
		Claims:        mwpClaims{Organisation: "CJIB"},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	c, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	obj, ok := c["mwp"].(map[string]any)
	if !ok {
		t.Fatalf("mwp object is missing or has wrong type: %T", c["mwp"])
	}
	if obj["organisation"] != "CJIB" {
		t.Errorf("mwp.organisation = %v", obj["organisation"])
	}
	if c["client_id"] != "client-abc" || !equalJSON(c["roles"], []any{"admin"}) {
		t.Errorf("top-level claims missing alongside nested object: client_id=%v roles=%v",
			c["client_id"], c["roles"])
	}
}

func TestIssueAccessTokenValidations(t *testing.T) {
	svc, _ := newAccessTokenService(t)

	// Claims without ClaimsKey.
	if _, err := svc.IssueAccessToken(token.AccessTokenRequest{
		CommonRequest: common(), ClientID: "c", Claims: mwpClaims{},
	}); !errors.Is(err, token.ErrMissingClaimsKey) {
		t.Fatalf("expected ErrMissingClaimsKey, got %v", err)
	}

	// Payload Validate() is honoured.
	if _, err := svc.IssueAccessToken(token.AccessTokenRequest{
		CommonRequest: common(), ClientID: "c", ClaimsKey: "acme-portal", Claims: acmeClaims{},
	}); !errors.Is(err, errMissingEmployeeID) {
		t.Fatalf("expected validation error from payload, got %v", err)
	}
}

// TestNewReservedClaimNames checks that the claims introduced by the access-token
// variant, and other registered names with defined access-token semantics,
// cannot be used as ClaimsKey by any variant.
func TestNewReservedClaimNames(t *testing.T) {
	svc, _ := newAccessTokenService(t)
	for _, key := range []string{
		"client_id", "scope", "roles", "name", "email", "preferred_username",
		"groups", "entitlements", "azp", "cnf", "sid", "given_name", "family_name",
	} {
		t.Run(key, func(t *testing.T) {
			if _, err := svc.IssueAccessToken(token.AccessTokenRequest{
				CommonRequest: common(), ClientID: "c", ClaimsKey: key, Claims: mwpClaims{},
			}); !errors.Is(err, token.ErrReservedClaimsKey) {
				t.Errorf("IssueAccessToken: expected ErrReservedClaimsKey, got %v", err)
			}
			if _, err := svc.IssueCustom(token.CustomRequest{
				CommonRequest: common(), Type: "x", ClaimsKey: key, Claims: mwpClaims{},
			}); !errors.Is(err, token.ErrReservedClaimsKey) {
				t.Errorf("IssueCustom: expected ErrReservedClaimsKey, got %v", err)
			}
		})
	}
}
