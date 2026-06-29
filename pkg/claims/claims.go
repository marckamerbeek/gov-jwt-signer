// SPDX-License-Identifier: EUPL-1.2

// Package claims contains the typed claim structs and assurance levels for the
// different token variants. The package deliberately has no external
// dependencies, so the domain models are decoupled from the JOSE implementation.
package claims

import "errors"

// TokenType identifies the variant of an issued token. The value is included as
// a private claim (by default "token_type", see DefaultTokenTypeClaim) so
// that verifiers can determine the token type explicitly. Besides the built-in
// variants below, callers may supply their own TokenType for custom variants.
type TokenType string

const (
	TokenTypeEIDAS       TokenType = "eidas"
	TokenTypeDigiD       TokenType = "digid"
	TokenTypeEHerkenning TokenType = "eherkenning"
)

// DefaultTokenTypeClaim is the default name of the private claim carrying the
// token type. Override it via extauthsec.WithTokenTypeClaim to use your own
// collision-resistant namespace (RFC 7519 §4.3), e.g. "example_token_type".
const DefaultTokenTypeClaim = "token_type"

// Validation errors of the claim structs.
var (
	ErrMissingSubject          = errors.New("claims: subject is missing")
	ErrMissingPersonIdentifier = errors.New("claims: eIDAS PersonIdentifier is missing")
	ErrMissingFamilyName       = errors.New("claims: eIDAS CurrentFamilyName is missing")
	ErrMissingGivenName        = errors.New("claims: eIDAS CurrentGivenName is missing")
	ErrMissingDateOfBirth      = errors.New("claims: eIDAS DateOfBirth is missing")
	ErrInvalidDateOfBirth      = errors.New("claims: DateOfBirth must use the format YYYY-MM-DD")
	ErrMissingDigiDIdentifier  = errors.New("claims: DigiD requires a BSN or pseudonym")
	ErrMissingDigiDLevel       = errors.New("claims: DigiD assurance level is missing")
	ErrMissingEHEntity         = errors.New("claims: eHerkenning requires an entity identifier (OIN, KvK or RSIN)")
	ErrMissingEHActingSubject  = errors.New("claims: eHerkenning acting_subject_id is missing")
	ErrMissingEHAssurance      = errors.New("claims: eHerkenning assurance class is missing")
	ErrInvalidAssuranceLevel   = errors.New("claims: unknown assurance level")
)
