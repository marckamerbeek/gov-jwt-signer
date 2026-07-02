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
		t.Fatalf("valid eIDAS: unexpected error %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*EIDAS)
		wantErr error
	}{
		{"no PersonIdentifier", func(e *EIDAS) { e.PersonIdentifier = "" }, ErrMissingPersonIdentifier},
		{"no FamilyName", func(e *EIDAS) { e.FamilyName = "" }, ErrMissingFamilyName},
		{"no GivenName", func(e *EIDAS) { e.GivenName = "" }, ErrMissingGivenName},
		{"no DateOfBirth", func(e *EIDAS) { e.DateOfBirth = "" }, ErrMissingDateOfBirth},
		{"bad date format", func(e *EIDAS) { e.DateOfBirth = "02-01-1980" }, ErrInvalidDateOfBirth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := valid
			tc.mutate(&e)
			if err := e.Validate(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDigiDValidate(t *testing.T) {
	if err := (DigiD{AssuranceLevel: DigiDHoog}).Validate(); !errors.Is(err, ErrMissingDigiDIdentifier) {
		t.Fatalf("no identifier: expected ErrMissingDigiDIdentifier, got %v", err)
	}
	if err := (DigiD{BSN: "123456782"}).Validate(); !errors.Is(err, ErrMissingDigiDLevel) {
		t.Fatalf("no level: expected ErrMissingDigiDLevel, got %v", err)
	}
	if err := (DigiD{BSN: "123456782", AssuranceLevel: "invalid"}).Validate(); !errors.Is(err, ErrInvalidAssuranceLevel) {
		t.Fatalf("invalid level: expected ErrInvalidAssuranceLevel, got %v", err)
	}
	if err := (DigiD{Pseudonym: "abc", AssuranceLevel: DigiDSubstantieel}).Validate(); err != nil {
		t.Fatalf("valid DigiD with pseudonym: unexpected error %v", err)
	}
}

func TestEHerkenningValidate(t *testing.T) {
	if err := (EHerkenning{ActingSubjectID: "x", AssuranceClass: EHLoA3}).Validate(); !errors.Is(err, ErrMissingEHEntity) {
		t.Fatalf("no entity: expected ErrMissingEHEntity, got %v", err)
	}
	if err := (EHerkenning{OIN: "00000001", AssuranceClass: EHLoA3}).Validate(); !errors.Is(err, ErrMissingEHActingSubject) {
		t.Fatalf("no acting subject: expected ErrMissingEHActingSubject, got %v", err)
	}
	if err := (EHerkenning{OIN: "00000001", ActingSubjectID: "x"}).Validate(); !errors.Is(err, ErrMissingEHAssurance) {
		t.Fatalf("no assurance: expected ErrMissingEHAssurance, got %v", err)
	}
	if err := (EHerkenning{OIN: "00000001", ActingSubjectID: "x", AssuranceClass: "urn:unknown"}).Validate(); !errors.Is(err, ErrInvalidAssuranceLevel) {
		t.Fatalf("invalid assurance: expected ErrInvalidAssuranceLevel, got %v", err)
	}
	if err := (EHerkenning{KvK: "12345678", ActingSubjectID: "x", AssuranceClass: EHLoA4}).Validate(); err != nil {
		t.Fatalf("valid eHerkenning: unexpected error %v", err)
	}
}

func TestAssuranceLevelValid(t *testing.T) {
	for _, a := range []AssuranceLevel{LoALow, LoASubstantial, LoAHigh} {
		if !a.Valid() {
			t.Errorf("%q should be valid", a)
		}
	}
	if AssuranceLevel("http://example.com/loa/nonsense").Valid() {
		t.Error("unknown LoA should be invalid")
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
			t.Errorf("%q -> %q, expected %q", cls, got, want)
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
			t.Errorf("%q -> %q, expected %q", lvl, got, want)
		}
	}
}
