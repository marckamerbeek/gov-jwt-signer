// SPDX-License-Identifier: EUPL-1.2

package claims

// AssuranceLevel is an eIDAS Level of Assurance as defined in Article 8 of
// Regulation (EU) 910/2014 and identified via the official URIs. This value
// belongs in the OIDC standard claim "acr" (Authentication Context Class
// Reference).
type AssuranceLevel string

const (
	LoALow         AssuranceLevel = "http://eidas.europa.eu/LoA/low"
	LoASubstantial AssuranceLevel = "http://eidas.europa.eu/LoA/substantial"
	LoAHigh        AssuranceLevel = "http://eidas.europa.eu/LoA/high"
)

// Valid reports whether the value is a recognised eIDAS level.
func (a AssuranceLevel) Valid() bool {
	switch a {
	case LoALow, LoASubstantial, LoAHigh:
		return true
	default:
		return false
	}
}

// EHerkenningAssuranceClass is an assurance class from the Afsprakenstelsel
// eToegang (eHerkenning/eIDAS). Source: Afsprakenstelsel eToegang.
type EHerkenningAssuranceClass string

const (
	EHLoA2     EHerkenningAssuranceClass = "urn:etoegang:core:assurance-class:loa2"     // EH2  (low)
	EHLoA2Plus EHerkenningAssuranceClass = "urn:etoegang:core:assurance-class:loa2plus" // EH2+ (low+)
	EHLoA3     EHerkenningAssuranceClass = "urn:etoegang:core:assurance-class:loa3"     // EH3  (substantial)
	EHLoA4     EHerkenningAssuranceClass = "urn:etoegang:core:assurance-class:loa4"     // EH4  (high)
)

// Valid reports whether the value is a recognised eHerkenning class.
func (c EHerkenningAssuranceClass) Valid() bool {
	switch c {
	case EHLoA2, EHLoA2Plus, EHLoA3, EHLoA4:
		return true
	default:
		return false
	}
}

// EIDAS maps an eHerkenning class to the corresponding eIDAS level, so the acr
// claim can be filled consistently.
//
//	LoA2 / LoA2+ -> low
//	LoA3         -> substantial
//	LoA4         -> high
func (c EHerkenningAssuranceClass) EIDAS() AssuranceLevel {
	switch c {
	case EHLoA3:
		return LoASubstantial
	case EHLoA4:
		return LoAHigh
	default:
		return LoALow
	}
}

// DigiDLevel is a DigiD assurance level (Logius).
type DigiDLevel string

const (
	DigiDBasis        DigiDLevel = "basis"
	DigiDMidden       DigiDLevel = "midden"
	DigiDSubstantieel DigiDLevel = "substantieel"
	DigiDHoog         DigiDLevel = "hoog"
)

// Valid reports whether the value is a recognised DigiD level.
func (l DigiDLevel) Valid() bool {
	switch l {
	case DigiDBasis, DigiDMidden, DigiDSubstantieel, DigiDHoog:
		return true
	default:
		return false
	}
}

// EIDAS maps a DigiD level to the corresponding eIDAS level.
//
// DigiD is notified to the EU at the levels Substantieel (=substantial) and Hoog
// (=high). Basis and Midden fall under eIDAS "low". Verify this mapping against
// the current Logius publication before using it in production.
func (l DigiDLevel) EIDAS() AssuranceLevel {
	switch l {
	case DigiDSubstantieel:
		return LoASubstantial
	case DigiDHoog:
		return LoAHigh
	default:
		return LoALow
	}
}
