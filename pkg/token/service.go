// SPDX-License-Identifier: EUPL-1.2

// Package token provides a high-level service that, per token variant, assembles
// the registered claims and the domain-specific claims and signs them via the
// Signer.
//
// All variants share exactly the same base: the same header (alg, typ, kid), the
// same registered claims (iss, sub, aud, iat, nbf, exp, jti) and, where
// applicable, the OIDC claims acr/amr/auth_time. Only the embedded variant object
// differs.
package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	extauthsec "github.com/marckamerbeek/gov-jwt-signer"
	"github.com/marckamerbeek/gov-jwt-signer/pkg/claims"
)

// Sentinel errors for custom token issuance. Use errors.Is() to match against them.
var (
	// ErrMissingTokenType is returned when a CustomRequest has no Type.
	ErrMissingTokenType = errors.New("token: custom Type is missing")

	// ErrMissingClaimsKey is returned when a CustomRequest carries Claims but no
	// ClaimsKey to nest them under.
	ErrMissingClaimsKey = errors.New("token: custom ClaimsKey is missing")

	// ErrReservedClaimsKey is returned when a CustomRequest's ClaimsKey collides
	// with a reserved top-level claim name (e.g. "iss", "acr", the token-type claim).
	ErrReservedClaimsKey = errors.New("token: ClaimsKey collides with a reserved claim")
)

// reservedClaimNames are the top-level claims a custom variant may not overwrite
// with its ClaimsKey. The configurable token-type claim is checked separately.
var reservedClaimNames = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {},
	"acr": {}, "amr": {}, "auth_time": {},
}

// Service assembles tokens and signs them.
type Service struct {
	signer *extauthsec.Signer
}

// NewService creates a Service around a configured Signer.
func NewService(signer *extauthsec.Signer) (*Service, error) {
	if signer == nil {
		return nil, fmt.Errorf("token: signer must not be nil")
	}
	return &Service{signer: signer}, nil
}

// CommonRequest contains the fields that every variant shares.
type CommonRequest struct {
	// Subject fills the sub claim. Required.
	Subject string
	// Audience fills the aud claim (the intended recipient(s) of the token).
	Audience []string
	// TTL is the validity duration; 0 means the Signer's default TTL.
	TTL time.Duration
	// AuthTime is the moment of authentication (OIDC auth_time); zero = omit.
	AuthTime time.Time
	// AMR are the Authentication Method References (RFC 8176), e.g. {"pwd","mfa"}.
	AMR []string
}

// tokenClaims is the assembled claim set for a single token. The standard claims
// are marshalled at the top level; the token type and the variant object are
// added under configurable keys by MarshalJSON, so a custom variant can nest its
// payload under any key without the library knowing the variant in advance.
type tokenClaims struct {
	jwt.RegisteredClaims
	acr            string
	amr            []string
	authTime       int64
	tokenType      claims.TokenType
	tokenTypeClaim string // JSON key for the token type
	variantKey     string // JSON key under which variant is nested ("" => none)
	variant        any    // variant-specific payload
}

// MarshalJSON assembles the final JWT payload: the standard claims, the token
// type under its configured claim name, and the variant object under its key.
func (c tokenClaims) MarshalJSON() ([]byte, error) {
	type standard struct {
		jwt.RegisteredClaims
		ACR      string   `json:"acr,omitempty"`
		AMR      []string `json:"amr,omitempty"`
		AuthTime int64    `json:"auth_time,omitempty"`
	}
	raw, err := json.Marshal(standard{c.RegisteredClaims, c.acr, c.amr, c.authTime})
	if err != nil {
		return nil, err
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if c.tokenType != "" {
		tt, err := json.Marshal(c.tokenType)
		if err != nil {
			return nil, err
		}
		m[c.tokenTypeClaim] = tt
	}
	if c.variantKey != "" && c.variant != nil {
		if _, exists := m[c.variantKey]; exists {
			return nil, fmt.Errorf("%w: %q", ErrReservedClaimsKey, c.variantKey)
		}
		v, err := json.Marshal(c.variant)
		if err != nil {
			return nil, err
		}
		m[c.variantKey] = v
	}
	return json.Marshal(m)
}

// EIDASRequest is an issuance request for an eIDAS token.
type EIDASRequest struct {
	CommonRequest
	LoA    claims.AssuranceLevel
	Person claims.EIDAS
}

// DigiDRequest is an issuance request for a DigiD token.
type DigiDRequest struct {
	CommonRequest
	Claims claims.DigiD
}

// EHerkenningRequest is an issuance request for an eHerkenning token.
type EHerkenningRequest struct {
	CommonRequest
	Claims claims.EHerkenning
}

// CustomRequest is an issuance request for a caller-defined token variant. It
// lets consumers of this library issue their own token type without modifying
// the library: pick a Type (the token-type claim value), a ClaimsKey (the JSON
// key the payload is nested under) and provide Claims (any JSON-serialisable
// value). If Claims implements interface{ Validate() error }, it is validated
// before signing.
type CustomRequest struct {
	CommonRequest
	// Type is the value placed in the token-type claim. Required.
	Type claims.TokenType
	// ClaimsKey is the top-level JSON key under which Claims is nested. Required
	// when Claims is non-nil. It must not collide with a reserved claim name.
	ClaimsKey string
	// ACR optionally fills the acr claim (e.g. an eIDAS LoA URI).
	ACR string
	// Claims is the variant-specific payload. May be nil for a type-only token.
	Claims any
}

// IssueEIDAS issues a signed eIDAS token. The acr claim is filled with the eIDAS
// LoA URI.
func (s *Service) IssueEIDAS(req EIDASRequest) (string, error) {
	if !req.LoA.Valid() {
		return "", claims.ErrInvalidAssuranceLevel
	}
	if err := req.Person.Validate(); err != nil {
		return "", err
	}
	return s.issue(req.CommonRequest, claims.TokenTypeEIDAS, string(req.LoA), "eidas", &req.Person)
}

// IssueDigiD issues a signed DigiD token. The acr claim is derived from the DigiD
// level via the eIDAS mapping.
func (s *Service) IssueDigiD(req DigiDRequest) (string, error) {
	if err := req.Claims.Validate(); err != nil {
		return "", err
	}
	acr := string(req.Claims.AssuranceLevel.EIDAS())
	return s.issue(req.CommonRequest, claims.TokenTypeDigiD, acr, "digid", &req.Claims)
}

// IssueEHerkenning issues a signed eHerkenning token. The acr claim is derived
// from the assurance class via the eIDAS mapping.
func (s *Service) IssueEHerkenning(req EHerkenningRequest) (string, error) {
	if err := req.Claims.Validate(); err != nil {
		return "", err
	}
	acr := string(req.Claims.AssuranceClass.EIDAS())
	return s.issue(req.CommonRequest, claims.TokenTypeEHerkenning, acr, "eherkenning", &req.Claims)
}

// IssueCustom issues a signed token for a caller-defined variant. See CustomRequest.
func (s *Service) IssueCustom(req CustomRequest) (string, error) {
	if req.Type == "" {
		return "", ErrMissingTokenType
	}
	if req.Claims != nil && req.ClaimsKey == "" {
		return "", ErrMissingClaimsKey
	}
	if req.ClaimsKey != "" {
		if _, reserved := reservedClaimNames[req.ClaimsKey]; reserved || req.ClaimsKey == s.signer.TokenTypeClaim() {
			return "", fmt.Errorf("%w: %q", ErrReservedClaimsKey, req.ClaimsKey)
		}
	}
	if v, ok := req.Claims.(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return "", err
		}
	}
	return s.issue(req.CommonRequest, req.Type, req.ACR, req.ClaimsKey, req.Claims)
}

// issue is the shared assembly core: it builds the base registered claims and
// signs a tokenClaims with the given type, acr and (optional) nested variant.
func (s *Service) issue(common CommonRequest, t claims.TokenType, acr, variantKey string, variant any) (string, error) {
	base, err := s.base(common)
	if err != nil {
		return "", err
	}
	return s.signer.Sign(tokenClaims{
		RegisteredClaims: base,
		acr:              acr,
		amr:              common.AMR,
		authTime:         authTime(common.AuthTime),
		tokenType:        t,
		tokenTypeClaim:   s.signer.TokenTypeClaim(),
		variantKey:       variantKey,
		variant:          variant,
	})
}

// base builds the shared registered claims.
func (s *Service) base(req CommonRequest) (jwt.RegisteredClaims, error) {
	if req.Subject == "" {
		return jwt.RegisteredClaims{}, claims.ErrMissingSubject
	}
	now := s.signer.Now()
	ttl := req.TTL
	if ttl <= 0 {
		ttl = s.signer.DefaultTTL()
	}
	jti, err := s.signer.NewJTI()
	if err != nil {
		return jwt.RegisteredClaims{}, err
	}
	return jwt.RegisteredClaims{
		Issuer:    s.signer.Issuer(),
		Subject:   req.Subject,
		Audience:  jwt.ClaimStrings(req.Audience),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		ID:        jti,
	}, nil
}

func authTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
