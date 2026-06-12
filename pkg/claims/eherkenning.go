// SPDX-License-Identifier: EUPL-1.2

package claims

// EHerkenning contains the claims for an organisation and acting person
// authenticated via eHerkenning (Afsprakenstelsel eToegang).
type EHerkenning struct {
	// Entity (the organisation). At least one identifier is required.
	OIN  string `json:"oin,omitempty"`        // Organisation identification number
	KvK  string `json:"kvk_number,omitempty"` // Chamber of Commerce number
	RSIN string `json:"rsin,omitempty"`       // Legal entities and partnerships information number

	// LegalSubjectID is the entityConcernedID as supplied by the broker.
	LegalSubjectID string `json:"legal_subject_id,omitempty"`

	// ActingSubjectID is the (encrypted) pseudonym of the acting person.
	// Required: identifies who acts on behalf of the organisation.
	ActingSubjectID string `json:"acting_subject_id"`

	// Service identification.
	ServiceID   string `json:"service_id,omitempty"`
	ServiceUUID string `json:"service_uuid,omitempty"`

	// AssuranceClass is the assurance class (LoA2..LoA4). Required.
	AssuranceClass EHerkenningAssuranceClass `json:"assurance_class"`
}

// Validate checks the required fields.
func (e EHerkenning) Validate() error {
	if e.OIN == "" && e.KvK == "" && e.RSIN == "" {
		return ErrMissingEHEntity
	}
	if e.ActingSubjectID == "" {
		return ErrMissingEHActingSubject
	}
	if e.AssuranceClass == "" {
		return ErrMissingEHAssurance
	}
	if !e.AssuranceClass.Valid() {
		return ErrInvalidAssuranceLevel
	}
	return nil
}
