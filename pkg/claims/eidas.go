// SPDX-License-Identifier: EUPL-1.2

package claims

import "time"

// eIDAS attribute namespaces from the eIDAS SAML Attribute Profile. The fields of
// EIDAS below are the minimum data set attributes; the official attribute URIs
// are given per field in comments so a mapping to SAML/eIDAS-Node is unambiguous.
const (
	EIDASNaturalPersonNamespace = "http://eidas.europa.eu/attributes/naturalperson/"
	EIDASLegalPersonNamespace   = "http://eidas.europa.eu/attributes/legalperson/"
)

// EIDAS contains the eIDAS minimum data set for a natural person
// (eIDAS SAML Attribute Profile, section "Attributes for Natural Persons").
type EIDAS struct {
	// PersonIdentifier is the uniqueness identifier. Required.
	// .../naturalperson/PersonIdentifier
	PersonIdentifier string `json:"person_identifier"`

	// FamilyName is the current family name. Required.
	// .../naturalperson/CurrentFamilyName
	FamilyName string `json:"family_name"`

	// GivenName is the current given name(s). Required.
	// .../naturalperson/CurrentGivenName
	GivenName string `json:"given_name"`

	// DateOfBirth in format YYYY-MM-DD (xsd:date). Required.
	// .../naturalperson/DateOfBirth
	DateOfBirth string `json:"date_of_birth"`

	// Optional attributes.
	BirthName      string `json:"birth_name,omitempty"`      // .../naturalperson/BirthName
	PlaceOfBirth   string `json:"place_of_birth,omitempty"`  // .../naturalperson/PlaceOfBirth
	CurrentAddress string `json:"current_address,omitempty"` // .../naturalperson/CurrentAddress
	Gender         string `json:"gender,omitempty"`          // .../naturalperson/Gender
	Nationality    string `json:"nationality,omitempty"`     // ISO 3166-1 alpha-2 ("EL" for Greece)
	CountryOfBirth string `json:"country_of_birth,omitempty"`
}

// Validate checks the required minimum-data-set attributes and the date format.
func (e EIDAS) Validate() error {
	switch {
	case e.PersonIdentifier == "":
		return ErrMissingPersonIdentifier
	case e.FamilyName == "":
		return ErrMissingFamilyName
	case e.GivenName == "":
		return ErrMissingGivenName
	case e.DateOfBirth == "":
		return ErrMissingDateOfBirth
	}
	if _, err := time.Parse("2006-01-02", e.DateOfBirth); err != nil {
		return ErrInvalidDateOfBirth
	}
	return nil
}
