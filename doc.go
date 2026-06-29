// SPDX-License-Identifier: EUPL-1.2

// Package extauthsec is the cryptographic core of gov-jwt-signer: a
// security module for signing JWTs within custom Gloo Gateway (Envoy) ExtAuth
// services.
//
// # Purpose
//
// The module signs several kinds of tokens that are identical at their core
// (same header, same set of registered claims, same key and kid) and differ only
// in their domain-specific claims. Three variants are built in:
//
//   - eIDAS  (EU interoperability; Regulation (EU) 910/2014)
//   - DigiD  (Logius; citizen authentication)
//   - eHerkenning (Afsprakenstelsel eToegang; organisation authentication)
//
// Consumers can additionally issue their own token variant via the token
// package's IssueCustom, so organisation-specific types live in the calling
// application rather than in this library. The name of the token-type claim
// (default "token_type") is configurable via WithTokenTypeClaim.
//
// # Standards
//
// The implementation follows the relevant IETF and domain standards:
//
//   - RFC 7519  JSON Web Token (JWT)
//   - RFC 7515  JSON Web Signature (JWS)
//   - RFC 7517  JSON Web Key (JWK / JWKS)
//   - RFC 7518  JSON Web Algorithms (JWA)
//   - RFC 7638  JWK Thumbprint (used as kid)
//   - eIDAS SAML Attribute Profile (minimum data set, LoA URIs)
//
// # Architecture
//
// The layering separates cryptography from domain logic:
//
//   - extauthsec (this package): key management, signing, JWKS, verification.
//   - .../pkg/claims: typed claim structs and assurance levels per variant,
//     without external dependencies.
//   - .../pkg/token: a high-level Service that assembles registered claims and
//     variant claims and signs them via the Signer.
//
// The only external dependency is github.com/golang-jwt/jwt/v5 (itself without
// transitive dependencies), which keeps the supply-chain surface minimal.
package extauthsec
