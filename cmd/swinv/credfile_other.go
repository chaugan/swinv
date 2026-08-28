//go:build !unix

package main

import (
	"fmt"
	"os"
)

// openCredential on non-unix opens the file without the POSIX ownership/mode
// checks (those bits are a fiction on Windows; ACLs are the real control and
// are the operator's to set). It still exists so callers share one code path.
func openCredential(path, what string) (*os.File, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied credential path
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return f, nil
}
