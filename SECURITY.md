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
- **Algorithm-confusion protection.** The `Verifier` requires `alg` on every JWK
  and enforces an algorithm allowlist derived from the JWKS. Tokens with
  `alg: none` or a deviating algorithm are rejected.
- **Key strength.** `NewSigner` rejects RSA keys below 2048 bits and EC keys on
  non-approved curves.
- **Audience at issuance.** `pkg/token.Service` requires a non-empty `aud` on
  every issued token.
- **JWKS integrity.** Duplicate `kid` values in a JWKS are rejected.
- **Key and algorithm checks.** When creating a `Signer`, it is verified that the
  key type matches the chosen algorithm (RSA for RS*/PS*, EC for ES*).
- **Safe defaults.** RS256 as the baseline (NL GOV Assurance profile), a required
  `exp`, and a `jti` with 128 bits of cryptographic entropy per token.

## Key management

Private keys do not belong in the repository. Provide them via a secret store or
a mounted file (`WithSigningKeyFile` / `WithSigningKeyPEM`). The `.gitignore`
excludes common key extensions as an extra safety net.

## Threat model

See [docs/threat-model.md](docs/threat-model.md) for trust boundaries, STRIDE
analysis, and an architecture diagram.

## Supported versions

Security updates are provided for the most recent minor release. Keep the Go
toolchain and `golang-jwt/jwt/v5` up to date; CI runs `govulncheck` and a Trivy
scan on every push and pull request.

## Post-quantum cryptography

This library deliberately does not yet support post-quantum signing algorithms (ML-DSA, SLH-DSA, or composite variants such as `MLDSA65-ES256`). This is an explicit choice, not an omission. The relevant standards and ecosystem support are not yet mature enough to make PQC for JWTs viable in production within the context this library was built for.

### Why not yet

**The IETF specifications are still drafts.** `draft-ietf-cose-dilithium` (ML-DSA for JOSE/COSE) and `draft-ietf-jose-pq-composite-sigs` have not been published as RFCs. The IANA JOSE registry has not yet assigned final `alg` values or the `PQK` key type. Early adoption carries the risk of breaking changes when the final RFC lands.

**No NL GOV Assurance profile extension.** The NL GOV Assurance profile for OAuth2 specifies RS256/PS256/ES256. Logius has not published a PQC extension. Without alignment with consuming government parties (Justid, DigiD, chain partners), early rollout leads to integration issues.

**Limited mature library support.** Go has no standard library support for ML-DSA. Implementations such as CIRCL are usable but not yet FIPS-certified. `golang-jwt/jwt/v5` does not recognise PQC algorithms. On the verifier side, Nimbus JOSE+JWT, jjwt, and comparable Java libraries have PQC on the roadmap, not in release.

**HSM and PKCS#11 support is fragmented.** ML-DSA in PKCS#11 was introduced in v3.2 (June 2024). Not all HSM vendors support it yet. For environments that rely on PKIoverheid HSMs, this is a blocker until the vendor catches up.

**Signature size causes practical problems.**

| Algorithm | Signature size |
|---|---|
| ES256 | 64 bytes |
| RS256 | 256 bytes |
| ML-DSA-44 | 2,420 bytes |
| ML-DSA-65 | 3,309 bytes |
| SLH-DSA-128s | 7,856 bytes |

A JWT signed with ML-DSA-65 no longer fits in a 4KB cookie. For bearer tokens in `Authorization` headers, `max_header_size` must be verified at every consuming component (Envoy, Tomcat, reverse proxies).

**HNDL is of limited relevance to JWS tokens.** "Store now, decrypt later" primarily threatens confidentiality (JWE, TLS). An intercepted signed JWT with a short `exp` gives an attacker with future quantum capacity little to work with: the token will long since have expired and become unusable. The urgency for PQC signing is therefore lower than for PQC key establishment.

**Composite implementations carry a known pitfall.** In hybrid/composite signatures the verifier must unconditionally validate both sub-signatures. An implementation that accidentally accepts a single valid sub-signature introduces a partial-verification bypass. Without broad reference implementations and test vectors, this is a real risk for in-house builds.

### What this library does provide

The architecture is prepared for crypto-agility so PQC support can be added later without breaking consumers:

- `alg` and JWK `kty` are not hardcoded anywhere in signing or JWKS logic
- Signer and verifier are abstracted so new algorithms can be added as drop-ins
- The RFC 7638 thumbprint implementation is separated per key type

### When PQC will be added

Inclusion becomes appropriate once at least the following holds:
- `draft-ietf-cose-dilithium` and `draft-ietf-jose-pq-composite-sigs` are published as RFCs
- IANA JOSE registry has assigned final algorithm identifiers
- Logius publishes a PQC extension to the NL GOV Assurance profile, or chain partners explicitly commit to a profile
- A FIPS-certified Go implementation exists, or alternatively a supported PKCS#11 route via the HSMs in use

Until then, the recommendation is: keep crypto-agility in order, keep key rotation procedures proven, and address PQC migration as part of the broader organisation-wide transition in line with the NCSC/AIVD PQC migration handbook and the Quantumveilige cryptografie NL (QvC NL) programme.
