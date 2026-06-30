// SPDX-License-Identifier: EUPL-1.2

// Command vault-sign demonstrates how an ExtAuth service fetches the active
// private signing key from the jwks-service Vault layout and uses this library
// to sign a JWT.
//
// It targets the key storage of github.com/sirrapa-it/jwks-service: a HashiCorp
// Vault KV v1 mount in which the rotator maintains
//
//	<secret-path>/active          {"kid": "...", "rotated_at": "..."}
//	<secret-path>/keys/<kid>      {"pem": "...", "kid": "...",
//	                               "created_at": "...", "expires_at": "..."}
//
// The active signing key is found by reading the /active pointer and then the
// matching /keys/<kid> record. The matching public key is published as a JWKS
// (RFC 7517) by the jwks-service server, so this example only needs the private
// key and the kid. The signer is configured with that same kid so verifiers can
// select the right key from the JWKS.
//
// Since the jwks-service derives the kid as the RFC 7638 JWK thumbprint, this
// library would compute the same kid from its default. We still pass the kid
// from Vault explicitly with WithKeyID: it is the service's source of truth and
// keeps the example correct regardless of how the kid was derived.
//
// To keep the module's dependency surface minimal (only golang-jwt), this
// example talks to Vault using the standard library: plain KV v1 reads over
// HTTP. In a production service you may prefer the official client
// github.com/hashicorp/vault/api, which handles auth methods, retries, renewal
// and namespaces for you.
//
// Configuration via environment variables:
//
//	VAULT_ADDR         Vault address (default http://127.0.0.1:8200)
//	VAULT_TOKEN        Vault token (required)
//	VAULT_KV_MOUNT     KV v1 mount path (default "secret")
//	VAULT_SECRET_PATH  key storage prefix (default "jwks-service")
//	ISSUER             iss claim for issued tokens (default https://signer.example.org)
//
// Run against a dev-mode Vault after the jwks-service rotator has run, or seed
// it manually:
//
//	vault kv put -mount=secret jwks-service/keys/<kid> \
//	    pem=@signing-key.pem kid=<kid> created_at=2026-01-01T00:00:00Z expires_at=
//	vault kv put -mount=secret jwks-service/active kid=<kid> rotated_at=2026-01-01T00:00:00Z
//	VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<token> go run ./examples/vault-sign
//
// Note: the jwks-service signs with RS256 (RSA-4096); this example assumes the
// same. Storing extractable private keys in Vault KV is one valid pattern. If
// you would rather keep the key inside Vault and never export it, use the
// Transit secrets engine and sign via its API instead; this library would then
// not be the signer.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	jwtsigner "github.com/marckamerbeek/gov-jwt-signer"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/claims"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/token"
)

// signingKey is the material the ExtAuth service needs to sign tokens. The public
// key lives in the JWKS published by the jwks-service server, not here.
type signingKey struct {
	PrivateKeyPEM []byte
	KID           string
}

func main() {
	addr := envOr("VAULT_ADDR", "http://127.0.0.1:8200")
	mount := envOr("VAULT_KV_MOUNT", "secret")
	secretPath := envOr("VAULT_SECRET_PATH", "jwks-service")
	issuer := envOr("ISSUER", "https://signer.example.org")

	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		log.Fatal("VAULT_TOKEN is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	key, err := fetchActiveSigningKey(ctx, addr, vaultToken, mount, secretPath)
	if err != nil {
		log.Fatalf("fetch signing key from Vault: %v", err)
	}

	// Configure the Signer with the key fetched from Vault. WithKeyID pins the kid
	// to the value the jwks-service published in the JWKS so verifiers can select
	// the right key. The jwks-service uses RS256 (RSA-4096), which is this
	// library's default algorithm.
	signer, err := jwtsigner.NewSigner(
		jwtsigner.WithIssuer(issuer),
		jwtsigner.WithSigningKeyPEM(key.PrivateKeyPEM),
		jwtsigner.WithKeyID(key.KID),
		jwtsigner.WithDefaultTTL(5*time.Minute),
	)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	svc, err := token.NewService(signer)
	if err != nil {
		log.Fatalf("create service: %v", err)
	}

	// Issue a token. Any of the built-in variants (or IssueCustom) works; here we
	// sign an eIDAS token as a concrete example.
	jwt, err := svc.IssueEIDAS(token.EIDASRequest{
		CommonRequest: token.CommonRequest{
			Subject:  "NL/NL/123456789",
			Audience: []string{"urn:service:consumer"},
			AMR:      []string{"pwd", "mfa"},
		},
		LoA: claims.LoAHigh,
		Person: claims.EIDAS{
			PersonIdentifier: "NL/NL/123456789",
			FamilyName:       "De Vries",
			GivenName:        "Anna",
			DateOfBirth:      "1990-05-17",
		},
	})
	if err != nil {
		log.Fatalf("issue token: %v", err)
	}

	fmt.Printf("kid: %s\nalg: %s\n\n%s\n", signer.KeyID(), signer.Algorithm(), jwt)
}

// fetchActiveSigningKey reads the active key id from the jwks-service /active
// pointer and then loads the matching key record from /keys/<kid>.
func fetchActiveSigningKey(ctx context.Context, addr, vaultToken, mount, secretPath string) (signingKey, error) {
	var active struct {
		Kid string `json:"kid"`
	}
	if err := readKVv1(ctx, addr, vaultToken, mount, secretPath+"/active", &active); err != nil {
		return signingKey{}, fmt.Errorf("read active pointer: %w", err)
	}
	if active.Kid == "" {
		return signingKey{}, fmt.Errorf("active pointer at %s/%s/active has no kid", mount, secretPath)
	}

	var record struct {
		PEM       string `json:"pem"`
		Kid       string `json:"kid"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := readKVv1(ctx, addr, vaultToken, mount, secretPath+"/keys/"+active.Kid, &record); err != nil {
		return signingKey{}, fmt.Errorf("read key record %s: %w", active.Kid, err)
	}
	if record.PEM == "" {
		return signingKey{}, fmt.Errorf("key record %s has no pem field", active.Kid)
	}
	// The active key carries an empty expires_at; a non-empty value means the
	// pointer is stale (the key is in its post-rotation grace period).
	if record.ExpiresAt != "" {
		return signingKey{}, fmt.Errorf("active key %s is expiring (expires_at=%q); rotator may be mid-rotation", active.Kid, record.ExpiresAt)
	}

	return signingKey{
		PrivateKeyPEM: []byte(record.PEM),
		KID:           record.Kid,
	}, nil
}

// readKVv1 performs a HashiCorp Vault KV v1 read and decodes the secret's
// key/value pairs into out. The KV v1 read endpoint is GET {addr}/v1/{mount}/{path};
// the values live directly under "data" in the response (KV v2 would nest them
// under data.data).
func readKVv1(ctx context.Context, addr, vaultToken, mount, path string, out any) error {
	endpoint := fmt.Sprintf("%s/v1/%s/%s", addr, url.PathEscape(mount), path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", vaultToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("call Vault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Vault returned status %d for %s", resp.StatusCode, endpoint)
	}

	var body struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode Vault response: %w", err)
	}
	if err := json.Unmarshal(body.Data, out); err != nil {
		return fmt.Errorf("decode secret data: %w", err)
	}
	return nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
