// SPDX-License-Identifier: EUPL-1.2

package claims

import (
	"errors"
	"testing"
)

func TestEIDASValidate(t *testing.T) {
	valid := EIDAS{
		PersonIdentifier: "NL/BE/12345",
		FamilyName:       "Jansen",
		GivenName:        "Jan",
		DateOfBirth:      "1980-01-02",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("geldige eIDAS: onverwachte fout %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*EIDAS)
		wantErr error
	}{
		{"geen PersonIdentifier", func(e *EIDAS) { e.PersonIdentifier = "" }, ErrMissingPersonIdentifier},
		{"geen FamilyName", func(e *EIDAS) { e.FamilyName = "" }, ErrMissingFamilyName},
		{"geen GivenName", func(e *EIDAS) { e.GivenName = "" }, ErrMissingGivenName},
		{"geen DateOfBirth", func(e *EIDAS) { e.DateOfBirth = "" }, ErrMissingDateOfBirth},
		{"fout datumformaat", func(e *EIDAS) { e.DateOfBirth = "02-01-1980" }, ErrInvalidDateOfBirth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := valid
			tc.mutate(&e)
			if err := e.Validate(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("verwacht %v, kreeg %v", tc.wantErr, err)
			}
		})
	}
}

func TestDigiDValidate(t *testing.T) {
	if err := (DigiD{Betrouwbaarheidsniveau: DigiDHoog}).Validate(); !errors.Is(err, ErrMissingDigiDIdentifier) {
		t.Fatalf("geen identifier: verwacht ErrMissingDigiDIdentifier, kreeg %v", err)
	}
	if err := (DigiD{BSN: "123456782"}).Validate(); !errors.Is(err, ErrMissingDigiDLevel) {
		t.Fatalf("geen niveau: verwacht ErrMissingDigiDLevel, kreeg %v", err)
	}
	if err := (DigiD{BSN: "123456782", Betrouwbaarheidsniveau: "ongeldig"}).Validate(); !errors.Is(err, ErrInvalidAssuranceLevel) {
		t.Fatalf("ongeldig niveau: verwacht ErrInvalidAssuranceLevel, kreeg %v", err)
	}
	if err := (DigiD{Pseudonym: "abc", Betrouwbaarheidsniveau: DigiDSubstantieel}).Validate(); err != nil {
		t.Fatalf("geldige DigiD met pseudoniem: onverwachte fout %v", err)
	}
}

func TestEHerkenningValidate(t *testing.T) {
	if err := (EHerkenning{ActingSubjectID: "x", AssuranceClass: EHLoA3}).Validate(); !errors.Is(err, ErrMissingEHEntity) {
		t.Fatalf("geen entiteit: verwacht ErrMissingEHEntity, kreeg %v", err)
	}
	if err := (EHerkenning{OIN: "00000001", AssuranceClass: EHLoA3}).Validate(); !errors.Is(err, ErrMissingEHActingSubject) {
		t.Fatalf("geen acting subject: verwacht ErrMissingEHActingSubject, kreeg %v", err)
	}
	if err := (EHerkenning{OIN: "00000001", ActingSubjectID: "x"}).Validate(); !errors.Is(err, ErrMissingEHAssurance) {
		t.Fatalf("geen assurance: verwacht ErrMissingEHAssurance, kreeg %v", err)
	}
	if err := (EHerkenning{OIN: "00000001", ActingSubjectID: "x", AssuranceClass: "urn:onbekend"}).Validate(); !errors.Is(err, ErrInvalidAssuranceLevel) {
		t.Fatalf("ongeldige assurance: verwacht ErrInvalidAssuranceLevel, kreeg %v", err)
	}
	if err := (EHerkenning{KvK: "12345678", ActingSubjectID: "x", AssuranceClass: EHLoA4}).Validate(); err != nil {
		t.Fatalf("geldige eHerkenning: onverwachte fout %v", err)
	}
}

func TestAssuranceLevelValid(t *testing.T) {
	for _, a := range []AssuranceLevel{LoALow, LoASubstantial, LoAHigh} {
		if !a.Valid() {
			t.Errorf("%q zou geldig moeten zijn", a)
		}
	}
	if AssuranceLevel("http://example.com/loa/onzin").Valid() {
		t.Error("onbekende LoA zou ongeldig moeten zijn")
	}
}

func TestEHerkenningEIDASMapping(t *testing.T) {
	cases := map[EHerkenningAssuranceClass]AssuranceLevel{
		EHLoA2:     LoALow,
		EHLoA2Plus: LoALow,
		EHLoA3:     LoASubstantial,
		EHLoA4:     LoAHigh,
	}
	for cls, want := range cases {
		if got := cls.EIDAS(); got != want {
			t.Errorf("%q -> %q, verwacht %q", cls, got, want)
		}
	}
}

func TestDigiDEIDASMapping(t *testing.T) {
	cases := map[DigiDLevel]AssuranceLevel{
		DigiDBasis:        LoALow,
		DigiDMidden:       LoALow,
		DigiDSubstantieel: LoASubstantial,
		DigiDHoog:         LoAHigh,
	}
	for lvl, want := range cases {
		if got := lvl.EIDAS(); got != want {
			t.Errorf("%q -> %q, verwacht %q", lvl, got, want)
		}
	}
}
