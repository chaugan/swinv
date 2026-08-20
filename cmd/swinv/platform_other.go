//go:build !windows

package main

import (
	"context"

	"github.com/chaugan/swinv/internal/scan"
)

// platformScan has nothing to do away from Windows: on Linux the filesystem is
// where the record of installed software lives, so the Syft scan is the right
// shape and runs as it always has. The false return says so.
func platformScan(context.Context, *config, func(string, ...any)) (*scan.Result, bool, error) {
	return nil, false, nil
}
