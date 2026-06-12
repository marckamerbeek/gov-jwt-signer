// SPDX-License-Identifier: EUPL-1.2

package claims

// Medewerkersportaal contains the claims for the internal employee portal. Where
// possible the standard OIDC claim names (RFC 7519 / OpenID Connect Core) are
// used, so consumers recognise them without mapping.
type Medewerkersportaal struct {
	// EmployeeID is the unique, internal employee identifier. Required.
	EmployeeID string `json:"employee_id"`

	// PreferredUsername is the login name (OIDC "preferred_username").
	PreferredUsername string `json:"preferred_username,omitempty"`

	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	Email      string `json:"email,omitempty"`

	// Department is the department or organisational unit.
	Department string `json:"department,omitempty"`

	// Organisation is the OIN of the organisation the employee belongs to.
	Organisation string `json:"organisation,omitempty"`

	// Roles and Groups carry authorization information for the ExtAuth chain.
	Roles  []string `json:"roles,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Validate checks the required fields.
func (m Medewerkersportaal) Validate() error {
	if m.EmployeeID == "" {
		return ErrMissingEmployeeID
	}
	return nil
}
