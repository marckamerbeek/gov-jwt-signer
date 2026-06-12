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
	"fmt"
	"time"

	extauthsec "github.com/cjib/gloo-gateway-extauth-sec"
	"github.com/cjib/gloo-gateway-extauth-sec/pkg/claims"
	"github.com/golang-jwt/jwt/v5"
)

// Service assembles tokens and signs them.
type Service struct {
	signer *extauthsec.Signer
}

// NewService creates a Service around a configured Signer.
func NewService(signer *extauthsec.Signer) (*Service, error) {
	if signer == nil {
		return nil, fmt.Errorf("token: signer mag niet nil zijn")
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

// tokenClaims is the assembled claim set. Thanks to the pointer fields with
// omitempty, only the relevant variant object appears in the payload.
type tokenClaims struct {
	jwt.RegisteredClaims
	ACR       string           `json:"acr,omitempty"`
	AMR       []string         `json:"amr,omitempty"`
	AuthTime  int64            `json:"auth_time,omitempty"`
	TokenType claims.TokenType `json:"cjib_token_type,omitempty"`

	Medewerkersportaal *claims.Medewerkersportaal `json:"medewerkersportaal,omitempty"`
	EIDAS              *claims.EIDAS              `json:"eidas,omitempty"`
	DigiD              *claims.DigiD              `json:"digid,omitempty"`
	EHerkenning        *claims.EHerkenning        `json:"eherkenning,omitempty"`
}

// MedewerkersportaalRequest is an issuance request for an internal employee token.
type MedewerkersportaalRequest struct {
	CommonRequest
	Claims claims.Medewerkersportaal
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

// IssueMedewerkersportaal issues a signed internal employee token.
func (s *Service) IssueMedewerkersportaal(req MedewerkersportaalRequest) (string, error) {
	if err := req.Claims.Validate(); err != nil {
		return "", err
	}
	base, err := s.base(req.CommonRequest)
	if err != nil {
		return "", err
	}
	c := tokenClaims{
		RegisteredClaims:   base,
		AMR:                req.AMR,
		AuthTime:           authTime(req.AuthTime),
		TokenType:          claims.TokenTypeMedewerkersportaal,
		Medewerkersportaal: &req.Claims,
	}
	return s.signer.Sign(c)
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
	base, err := s.base(req.CommonRequest)
	if err != nil {
		return "", err
	}
	c := tokenClaims{
		RegisteredClaims: base,
		ACR:              string(req.LoA),
		AMR:              req.AMR,
		AuthTime:         authTime(req.AuthTime),
		TokenType:        claims.TokenTypeEIDAS,
		EIDAS:            &req.Person,
	}
	return s.signer.Sign(c)
}

// IssueDigiD issues a signed DigiD token. The acr claim is derived from the DigiD
// level via the eIDAS mapping.
func (s *Service) IssueDigiD(req DigiDRequest) (string, error) {
	if err := req.Claims.Validate(); err != nil {
		return "", err
	}
	base, err := s.base(req.CommonRequest)
	if err != nil {
		return "", err
	}
	c := tokenClaims{
		RegisteredClaims: base,
		ACR:              string(req.Claims.Betrouwbaarheidsniveau.EIDAS()),
		AMR:              req.AMR,
		AuthTime:         authTime(req.AuthTime),
		TokenType:        claims.TokenTypeDigiD,
		DigiD:            &req.Claims,
	}
	return s.signer.Sign(c)
}

// IssueEHerkenning issues a signed eHerkenning token. The acr claim is derived
// from the assurance class via the eIDAS mapping.
func (s *Service) IssueEHerkenning(req EHerkenningRequest) (string, error) {
	if err := req.Claims.Validate(); err != nil {
		return "", err
	}
	base, err := s.base(req.CommonRequest)
	if err != nil {
		return "", err
	}
	c := tokenClaims{
		RegisteredClaims: base,
		ACR:              string(req.Claims.AssuranceClass.EIDAS()),
		AMR:              req.AMR,
		AuthTime:         authTime(req.AuthTime),
		TokenType:        claims.TokenTypeEHerkenning,
		EHerkenning:      &req.Claims,
	}
	return s.signer.Sign(c)
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
