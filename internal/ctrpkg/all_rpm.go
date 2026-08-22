package ctrpkg

import (
	"os"
	"path/filepath"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
)

// allRPM lists every package an RPM database records.
//
// go-rpmdb needs a file on disk, so a Source that is not already a directory
// has its database staged to a temporary file first. That is the price of
// reading a Berkeley DB through a runtime API, and it is paid only when the
// cheaper routes found nothing.
func allRPM(src Source, rel Release) []Owner {
	path, cleanup, err := stageRPMDB(src)
	if err != nil {
		return nil
	}
	defer cleanup()

	db, err := rpmdb.Open(path)
	if err != nil || db == nil {
		return nil
	}
	defer func() { _ = db.Close() }()

	packages, err := db.ListPackages()
	if err != nil {
		return nil
	}

	out := make([]Owner, 0, len(packages))
	for _, p := range packages {
		if p == nil || p.Name == "" {
			continue
		}
		version := rpmVersion(p.Epoch, p.Version, p.Release)
		out = append(out, Owner{
			Name: p.Name, Version: version, Arch: p.Arch, Type: "rpm",
			PURL: purl("rpm", rel, p.Name, version, p.Arch),
		})
	}
	return sorted(out)
}

// stageRPMDB gives go-rpmdb a path it can open.
func stageRPMDB(src Source) (string, func(), error) {
	noop := func() {}

	// A directory source can be opened where it lies.
	if d, ok := src.(DirSource); ok {
		if p := findRPMDB(d.Root); p != "" {
			return p, noop, nil
		}
		return "", noop, os.ErrNotExist
	}

	for _, dir := range rpmDBPaths {
		for _, name := range rpmDBFiles {
			raw, err := src.ReadFile("/" + dir + "/" + name)
			if err != nil || len(raw) == 0 {
				continue
			}
			f, err := os.CreateTemp("", "swinv-rpmdb-*")
			if err != nil {
				return "", noop, err
			}
			cleanup := func() {
				_ = f.Close()
				_ = os.Remove(f.Name())
			}
			if _, err := f.Write(raw); err != nil {
				cleanup()
				return "", noop, err
			}
			if err := f.Close(); err != nil {
				cleanup()
				return "", noop, err
			}
			return f.Name(), func() { _ = os.Remove(filepath.Clean(f.Name())) }, nil
		}
	}
	return "", noop, os.ErrNotExist
}
