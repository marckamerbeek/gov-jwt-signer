# Security

## Reporting vulnerabilities

Do not report suspected vulnerabilities via a public issue, but via the
maintainers' private security channel (see the repository settings for "Report a
vulnerability"). Where possible, include a reproducible scenario and the impact.
You will receive an acknowledgement of receipt as soon as possible.

## Principles

This module is deliberately designed with a small attack surface:

- **Minimal dependencies.** The only external dependency is
  `github.com/golang-jwt/jwt/v5`. JWK, JWKS and the RFC 7638 thumbprint are
  implemented with the Go standard library. This limits supply-chain risks.
- **Algorithm-confusion protection.** The `Verifier` uses an algorithm allowlist
  based on the JWKS. Tokens with `alg: none` or a deviating algorithm are
  rejected.
- **Key and algorithm checks.** When creating a `Signer`, it is verified that the
  key type matches the chosen algorithm (RSA for RS*/PS*, EC for ES*).
- **Safe defaults.** RS256 as the baseline (NL GOV Assurance profile), a required
  `exp`, and a `jti` with 128 bits of cryptographic entropy per token.

## Key management

Private keys do not belong in the repository. Provide them via a secret store or
a mounted file (`WithSigningKeyFile` / `WithSigningKeyPEM`). The `.gitignore`
excludes common key extensions as an extra safety net.

## Supported versions

Security updates are provided for the most recent minor release. Keep the Go
toolchain and `golang-jwt/jwt/v5` up to date; CI runs `govulncheck` and a Trivy
scan on every push and pull request.
