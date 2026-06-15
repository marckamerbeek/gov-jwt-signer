// SPDX-License-Identifier: EUPL-1.2

// Command vault-sign demonstrates how an ExtAuth service can fetch a PEM-encoded
// private signing key from HashiCorp Vault (KV v2) and use it with this library
// to sign a JWT.
//
// The matching public key is published as a JWKS (RFC 7517) by a separate
// service, so this example only needs the private key and the key id (kid) that
// the JWKS server assigned to it. The signer is configured with that same kid so
// verifiers can select the right key from the JWKS.
//
// To keep the module's dependency surface minimal (only golang-jwt), this
// example talks to Vault using the standard library: a plain KV v2 read over
// HTTP. In a production service you may prefer the official client
// github.com/hashicorp/vault/api, which handles auth methods, retries, renewal
// and namespaces for you.
//
// Configuration via environment variables:
//
//	VAULT_ADDR      Vault address (default http://127.0.0.1:8200)
//	VAULT_TOKEN     Vault token (required)
//	VAULT_KV_MOUNT  KV v2 mount path (default "secret")
//	VAULT_KEY_PATH  secret path holding the key (default "extauth/signing-key")
//	ISSUER          iss claim for issued tokens (default https://extauth.example.org)
//
// The Vault secret is expected to contain at least:
//
//	private_key  PEM-encoded private key (PKCS#8, PKCS#1 or SEC1)
//	kid          key id matching the one published in the JWKS (optional)
//	algorithm    JWS algorithm, e.g. "RS256" or "ES256" (optional, default RS256)
//
// Run against a dev-mode Vault:
//
//	vault kv put secret/extauth/signing-key \
//	    private_key=@signing-key.pem kid=my-key-1 algorithm=RS256
//	VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<token> go run ./examples/vault-sign
//
// Note: storing extractable private keys in Vault KV is one valid pattern. If you
// would rather keep the key inside Vault and never export it, use the Transit
// secrets engine and sign via its API instead; this library would then not be the
// signer.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	extauthsec "github.com/jwt-extauth/gloo-gateway-extauth-sec"
	"github.com/jwt-extauth/gloo-gateway-extauth-sec/pkg/claims"
	"github.com/jwt-extauth/gloo-gateway-extauth-sec/pkg/token"
)

// signingKey is the material the ExtAuth service needs to sign tokens. The public
// key lives in the JWKS published by the separate JWKS server, not here.
type signingKey struct {
	PrivateKeyPEM []byte
	KID           string
	Algorithm     extauthsec.Algorithm
}

func main() {
	addr := envOr("VAULT_ADDR", "http://127.0.0.1:8200")
	mount := envOr("VAULT_KV_MOUNT", "secret")
	path := envOr("VAULT_KEY_PATH", "extauth/signing-key")
	issuer := envOr("ISSUER", "https://extauth.example.org")

	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		log.Fatal("VAULT_TOKEN is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	key, err := fetchSigningKey(ctx, addr, vaultToken, mount, path)
	if err != nil {
		log.Fatalf("fetch signing key from Vault: %v", err)
	}

	// Configure the Signer with the key fetched from Vault. WithKeyID pins the kid
	// to the value published in the JWKS; if the secret has no kid, the library
	// derives the RFC 7638 thumbprint, which matches a JWKS server that does the
	// same.
	opts := []extauthsec.Option{
		extauthsec.WithIssuer(issuer),
		extauthsec.WithSigningKeyPEM(key.PrivateKeyPEM),
		extauthsec.WithAlgorithm(key.Algorithm),
		extauthsec.WithDefaultTTL(5 * time.Minute),
	}
	if key.KID != "" {
		opts = append(opts, extauthsec.WithKeyID(key.KID))
	}

	signer, err := extauthsec.NewSigner(opts...)
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

// fetchSigningKey reads the signing key from a Vault KV v2 secret. The KV v2 read
// endpoint is GET {addr}/v1/{mount}/data/{path}; the secret's key/value pairs are
// nested under data.data in the response (RFC-agnostic, this is Vault's shape).
func fetchSigningKey(ctx context.Context, addr, vaultToken, mount, path string) (signingKey, error) {
	url := fmt.Sprintf("%s/v1/%s/data/%s", addr, mount, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return signingKey{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", vaultToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return signingKey{}, fmt.Errorf("call Vault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return signingKey{}, fmt.Errorf("Vault returned status %d for %s", resp.StatusCode, url)
	}

	// KV v2 response: {"data":{"data":{<secret kv>},"metadata":{...}}}.
	var body struct {
		Data struct {
			Data struct {
				PrivateKey string `json:"private_key"`
				KID        string `json:"kid"`
				Algorithm  string `json:"algorithm"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return signingKey{}, fmt.Errorf("decode Vault response: %w", err)
	}

	secret := body.Data.Data
	if secret.PrivateKey == "" {
		return signingKey{}, fmt.Errorf("secret at %s/%s has no private_key field", mount, path)
	}

	alg := extauthsec.RS256
	if secret.Algorithm != "" {
		alg = extauthsec.Algorithm(secret.Algorithm)
	}

	return signingKey{
		PrivateKeyPEM: []byte(secret.PrivateKey),
		KID:           secret.KID,
		Algorithm:     alg,
	}, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
