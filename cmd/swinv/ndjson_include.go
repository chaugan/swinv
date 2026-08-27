package main

import (
	"fmt"
	"sort"
	"strings"
)

// ndjsonRecordTypes are the non-component records the NDJSON stream can carry,
// mapped from the name an operator types to the record_type emitted.
//
// "containers" rather than "container" on the command line because that is how
// the section reads in the report and in every other flag; the record itself
// stays singular, since each one describes one container.
var ndjsonRecordTypes = map[string]string{
	"exposure":   "exposure",
	"containers": "container",
	"links":      "link",
	"config":     "config",
}

// validateNDJSONInclude checks a --ndjson-include list and returns the record
// types it names.
//
// A typo is a usage error rather than a silent omission. Someone who writes
// --ndjson-include=exposures and gets no exposure records would reasonably
// conclude the feature is broken, and would be looking in the wrong place.
func validateNDJSONInclude(list string) ([]string, error) {
	var out []string
	seen := map[string]bool{}

	for _, name := range strings.Split(list, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if name == "all" {
			for _, recordType := range ndjsonRecordTypes {
				if !seen[recordType] {
					seen[recordType] = true
					out = append(out, recordType)
				}
			}
			continue
		}
		recordType, ok := ndjsonRecordTypes[name]
		if !ok {
			return nil, fmt.Errorf("unknown --ndjson-include %q (want one of: %s, or all)",
				name, strings.Join(ndjsonIncludeNames(), ", "))
		}
		if !seen[recordType] {
			seen[recordType] = true
			out = append(out, recordType)
		}
	}
	sort.Strings(out)
	return out, nil
}

// parseNDJSONInclude returns the record types, having already been validated.
func parseNDJSONInclude(list string) []string {
	out, _ := validateNDJSONInclude(list)
	return out
}

// ndjsonIncludeNames returns the accepted names, sorted, for error messages.
func ndjsonIncludeNames() []string {
	out := make([]string, 0, len(ndjsonRecordTypes))
	for name := range ndjsonRecordTypes {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
