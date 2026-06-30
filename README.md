# gov-jwt-signer

A Go security module for signing JSON Web Tokens (JWTs) inside custom Envoy
external authorization (ExtAuth) services. The module issues token variants that
are identical at their core (same header, same registered claims, same signing)
and differ only in their domain-specific claims. Three variants are built in:

- **eIDAS** — the European standard for cross-border authentication
- **DigiD** — citizen authentication (Logius)
- **eHerkenning** — authentication of organisations and acting persons

In addition, consumers of this library can define their **own token type** via
`IssueCustom`, without modifying the library. This keeps the module free of
organisation-specific variants (see [Custom token type](#custom-token-type)).

The module is built around existing standards and with a minimal supply-chain
surface: the only external dependency is
[`golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt). JWK, JWKS and the
RFC 7638 thumbprint are implemented with the standard library.

## Standards

| Topic | Standard |
|-------|----------|
| JWT | RFC 7519 |
| JWS (signing) | RFC 7515 |
| JWK / JWKS | RFC 7517 |
| Algorithms | RFC 7518 |
| JWK Thumbprint (kid) | RFC 7638 |
| Authentication Method References (amr) | RFC 8176 |
| eIDAS minimum data set | eIDAS SAML Attribute Profile (Regulation (EU) 910/2014) |
| Assurance levels (acr) | eIDAS LoA low/substantial/high |
| eHerkenning | Afsprakenstelsel eToegang |

The default algorithm is **RS256**, in line with the baseline of the NL GOV
Assurance profile for OAuth 2.0. Use `WithAlgorithm` to switch to, among others,
PS256 or ES256.

## Architecture

The module is layered so that the domain models are decoupled from the JOSE
implementation:

```
extauthsec/                root package: Signer, Verifier, key and JWKS logic
├── pkg/claims/            typed claim structs + assurance levels (no external deps)
└── pkg/token/             Service that assembles and signs claims per variant
```

- `extauthsec.Signer` — immutable and concurrency-safe; signs an arbitrary
  `jwt.Claims` and publishes the corresponding JWKS.
- `extauthsec.Verifier` — validates issued tokens (kid matching, algorithm
  allowlist against algorithm confusion, exp/nbf, iss/aud). Intended for
  self-testing and lightweight verification; production verifiers in other
  services use their own JOSE library.
- `pkg/token.Service` — provides an `Issue...` method per built-in variant plus
  the generic `IssueCustom` for custom token types.

### Claim layout

The OIDC standard claims live at the top level (`iss`, `sub`, `aud`, `exp`,
`nbf`, `iat`, `jti`, and where applicable `acr`, `amr`, `auth_time`). The
variant-specific data is nested under its own key (`eidas`, `digid`,
`eherkenning`, or for a custom variant a key chosen by the consumer). The private
claim `token_type` names the token type explicitly.

The name of that claim is configurable via `WithTokenTypeClaim` (default
`token_type`), so organisations can use their own collision-resistant namespace
(RFC 7519 §4.3), for example `example_token_type`.

The `acr` claim is filled with the eIDAS LoA URI: directly for eIDAS, derived for
DigiD and eHerkenning (see the `EIDAS()` mappings). For a custom variant the
consumer determines the `acr` value (optional).

### Custom token type

An application that uses this library can issue its own token type without
modifying the library. The payload is an ordinary struct owned by the consumer;
if it implements `Validate() error`, that is called before signing. The
`ClaimsKey` must not collide with a reserved claim.

```go
type AcmeClaims struct {
	EmployeeID string   `json:"employee_id"`
	Roles      []string `json:"roles,omitempty"`
}

func (p AcmeClaims) Validate() error {
	if p.EmployeeID == "" {
		return errors.New("employee_id is missing")
	}
	return nil
}

jwt, err := svc.IssueCustom(token.CustomRequest{
	CommonRequest: token.CommonRequest{Subject: "emp-00421", Audience: []string{"acme-portal-api"}},
	Type:          "acme-portal", // value of the token_type claim
	ClaimsKey:     "acme-portal", // key under which the payload is nested
	ACR:           "",            // optional
	Claims:        AcmeClaims{EmployeeID: "00421", Roles: []string{"admin"}},
})
```

## Installation

```sh
go get github.com/marckamerbeek/gov-jwt-signer
```

Requires Go 1.22 or newer.

## Usage

```go
package main

import (
	"fmt"
	"log"

	extauthsec "github.com/marckamerbeek/gov-jwt-signer"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/claims"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/token"
)

func main() {
	signer, err := extauthsec.NewSigner(
		extauthsec.WithIssuer("https://extauth.example.org"),
		extauthsec.WithSigningKeyFile("/etc/extauth/signing-key.pem"),
		// extauthsec.WithAlgorithm(extauthsec.PS256), // optional
	)
	if err != nil {
		log.Fatal(err)
	}

	svc, err := token.NewService(signer)
	if err != nil {
		log.Fatal(err)
	}

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
		log.Fatal(err)
	}
	fmt.Println(jwt)

	// Publish the JWKS at the well-known endpoint.
	jwksJSON, _ := signer.JWKSJSON()
	fmt.Println(string(jwksJSON))
}
```

A complete working example that issues the three built-in variants plus a custom
variant, prints the JWKS and verifies a token can be found in
[`examples/basic`](examples/basic/main.go):

```sh
go run ./examples/basic
```

## Key management

- Provide the private key as PEM via `WithSigningKeyPEM` (bytes) or
  `WithSigningKeyFile` (path). PKCS#8, PKCS#1 and SEC1 are supported.
- By default the `kid` is computed as the RFC 7638 thumbprint of the public key,
  so key rotation is unambiguous and cache-friendly. Use `WithKeyID` to supply
  your own `kid`.
- Publish `signer.JWKS()` / `signer.JWKSJSON()` on a JWKS endpoint so consumers
  can validate the signature.

## Integration with jwks-service

In a cluster, key generation, rotation and JWKS publication are typically
delegated to a dedicated trust anchor such as
[jwks-service](https://github.com/sirrapa-it/jwks-service). It manages one shared
RSA keypair in HashiCorp Vault, rotates it on a schedule, and serves the public
keys at `/.well-known/jwks.json`. This library is then only the **signer** inside
the ExtAuth service; verifiers fetch the JWKS from the service, not from
`signer.JWKS()` (which becomes a self-test helper).

The signer obtains its key from Vault rather than from a local file:

- jwks-service stores keys in a **KV v1** mount as `<path>/keys/<kid>`
  (`pem`, `kid`, `created_at`, `expires_at`) with an `<path>/active` pointer to
  the current signing key. Read the pointer, load the matching record, and pass
  the PKCS#1 PEM with `WithSigningKeyPEM` plus `WithKeyID(<kid>)`.
- **The `kid` must match the value the service publishes.** Set it explicitly
  with `WithKeyID` from the Vault record. (jwks-service derives the `kid` as the
  RFC 7638 thumbprint, the same scheme this library uses by default, so the two
  agree — but taking the published value is authoritative regardless.)
- Keys rotate, and a `Signer` is immutable, so reload the active key periodically
  and rebuild the `Signer`. Tokens are short-lived and rotated keys stay in the
  JWKS during a grace period, so a periodic refresh avoids signing under a key
  that has left the JWKS.

See [`examples/vault-sign`](examples/vault-sign/main.go) for a runnable example
against this layout:

```sh
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<token> go run ./examples/vault-sign
```

## Development

```sh
make build     # compile
make test      # tests with the race detector and coverage
make vet       # go vet
make lint      # golangci-lint (if installed)
make vuln      # govulncheck
make tidy      # go mod tidy
```

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities and the security
principles of this module.

## License

Released under the **EUPL-1.2**. See [LICENSE](LICENSE).
