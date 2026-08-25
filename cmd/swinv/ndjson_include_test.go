package main

import (
	"reflect"
	"testing"
)

func TestValidateNDJSONInclude(t *testing.T) {
	cases := map[string][]string{
		"":                        nil,
		"exposure":                {"exposure"},
		"containers":              {"container"},
		"exposure,containers":     {"container", "exposure"},
		" Exposure , Containers ": {"container", "exposure"},
		"all":                     {"container", "exposure", "link"},
		"exposure,exposure":       {"exposure"},
	}
	for in, want := range cases {
		got, err := validateNDJSONInclude(in)
		if err != nil {
			t.Errorf("validateNDJSONInclude(%q): %v", in, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("validateNDJSONInclude(%q) = %v, want %v", in, got, want)
		}
	}
}

// A typo must be a usage error rather than a silent omission: someone who
// writes "exposures" and gets no records would conclude the feature is broken
// and look in the wrong place.
func TestValidateNDJSONIncludeRejectsTypos(t *testing.T) {
	for _, in := range []string{"exposures", "container", "services", "all,nonsense"} {
		if _, err := validateNDJSONInclude(in); err == nil {
			t.Errorf("validateNDJSONInclude(%q) was accepted", in)
		}
	}
}

// The flag name is plural and the record type singular; each record describes
// one container.
func TestNDJSONIncludeNamesMapToRecordTypes(t *testing.T) {
	if ndjsonRecordTypes["containers"] != "container" {
		t.Errorf("containers maps to %q", ndjsonRecordTypes["containers"])
	}
	if ndjsonRecordTypes["exposure"] != "exposure" {
		t.Errorf("exposure maps to %q", ndjsonRecordTypes["exposure"])
	}
}
