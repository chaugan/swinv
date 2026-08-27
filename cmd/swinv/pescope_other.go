//go:build !windows

package main

import "github.com/chaugan/swinv/internal/model"

// attachPELinks reads PE import tables, which exist on Windows binaries; the
// ELF probe covers this ground here.
func attachPELinks(*config, *model.Report, func(string, ...any)) {}
