// SPDX-License-Identifier: EUPL-1.2

package claims

// DigiD contains the claims for a citizen authenticated via DigiD (Logius).
//
// Note: the BSN is special category personal data. Prefer a sectoral pseudonym
// (Pseudonym) when the consuming service does not need the BSN, in line with data
// minimisation.
type DigiD struct {
	// BSN is the citizen service number. Optional if Pseudonym is set.
	BSN string `json:"bsn,omitempty"`

	// Pseudonym is a sectoral/polymorphic pseudonym. Optional if BSN is set.
	Pseudonym string `json:"pseudonym,omitempty"`

	// AssuranceLevel is the DigiD level (basis/midden/substantieel/hoog).
	// Required.
	AssuranceLevel DigiDLevel `json:"betrouwbaarheidsniveau"`
}

// Validate checks that an identifier and a valid level are present.
func (d DigiD) Validate() error {
	if d.BSN == "" && d.Pseudonym == "" {
		return ErrMissingDigiDIdentifier
	}
	if d.AssuranceLevel == "" {
		return ErrMissingDigiDLevel
	}
	if !d.AssuranceLevel.Valid() {
		return ErrInvalidAssuranceLevel
	}
	return nil
}
