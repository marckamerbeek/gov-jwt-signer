// SPDX-License-Identifier: EUPL-1.2

// Package claims contains the typed claim structs and assurance levels for the
// different token variants. The package deliberately has no external
// dependencies, so the domain models are decoupled from the JOSE implementation.
package claims

import "errors"

// TokenType identifies the variant of an issued token. The value is included as
// the private claim "cjib_token_type" in the JWT so that verifiers can determine
// the token type explicitly.
type TokenType string

const (
	TokenTypeMedewerkersportaal TokenType = "medewerkersportaal"
	TokenTypeEIDAS              TokenType = "eidas"
	TokenTypeDigiD              TokenType = "digid"
	TokenTypeEHerkenning        TokenType = "eherkenning"
)

// TokenTypeClaim is the name of the private claim carrying the token type.
// The "cjib_" prefix serves as a collision-resistant namespace (RFC 7519 §4.3).
const TokenTypeClaim = "cjib_token_type"

// Validation errors of the claim structs.
var (
	ErrMissingSubject          = errors.New("claims: subject ontbreekt")
	ErrMissingEmployeeID       = errors.New("claims: employee_id ontbreekt")
	ErrMissingPersonIdentifier = errors.New("claims: eIDAS PersonIdentifier ontbreekt")
	ErrMissingFamilyName       = errors.New("claims: eIDAS CurrentFamilyName ontbreekt")
	ErrMissingGivenName        = errors.New("claims: eIDAS CurrentGivenName ontbreekt")
	ErrMissingDateOfBirth      = errors.New("claims: eIDAS DateOfBirth ontbreekt")
	ErrInvalidDateOfBirth      = errors.New("claims: DateOfBirth moet het formaat YYYY-MM-DD hebben")
	ErrMissingDigiDIdentifier  = errors.New("claims: DigiD vereist een BSN of pseudoniem")
	ErrMissingDigiDLevel       = errors.New("claims: DigiD betrouwbaarheidsniveau ontbreekt")
	ErrMissingEHEntity         = errors.New("claims: eHerkenning vereist een entiteit-identificatie (OIN, KvK of RSIN)")
	ErrMissingEHActingSubject  = errors.New("claims: eHerkenning acting_subject_id ontbreekt")
	ErrMissingEHAssurance      = errors.New("claims: eHerkenning assurance class ontbreekt")
	ErrInvalidAssuranceLevel   = errors.New("claims: onbekend betrouwbaarheidsniveau")
)
