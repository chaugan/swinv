//go:build !windows

package main

import (
	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/scan"
)

// attachPELinks reads PE import tables, which exist on Windows binaries; the
// ELF probe covers this ground here.
func attachPELinks(*config, *model.Report, *scan.Result, func(string, ...any)) {}
