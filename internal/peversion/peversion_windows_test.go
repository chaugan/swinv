//go:build windows

package peversion

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestReadSystemBinary checks extraction against a file present on every
// Windows installation, whose values are known well enough to assert on.
func TestReadSystemBinary(t *testing.T) {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll")

	info, err := Read(path)
	if err != nil {
		t.Fatalf("Read(%s): %v", path, err)
	}

	t.Logf("ProductName:      %q", info.ProductName)
	t.Logf("CompanyName:      %q", info.CompanyName)
	t.Logf("FileDescription:  %q", info.FileDescription)
	t.Logf("FileVersion:      %q", info.FileVersion)
	t.Logf("ProductVersion:   %q", info.ProductVersion)
	t.Logf("FixedFileVersion: %q", info.FixedFileVersion)

	if info.CompanyName == "" {
		t.Error("no CompanyName: this is the field that makes a .dll attributable to a publisher")
	}
	if info.FixedFileVersion == "" {
		t.Error("no FixedFileVersion: the numeric version cannot be malformed and should always be present")
	}
	if info.FixedFileVersion == "0.0.0.0" {
		t.Errorf("FixedFileVersion = %q, which means the fixed-info block was misread", info.FixedFileVersion)
	}
}

// TestReadEveryFlavourOfSystem32 runs over a spread of real binaries. The
// point is not any single file but that extraction survives the variety --
// localised resources, missing string tables, unusual translations -- without
// erroring on anything except a genuine absence of version info.
func TestReadEveryFlavourOfSystem32(t *testing.T) {
	dir := filepath.Join(os.Getenv("SystemRoot"), "System32")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("cannot read %s: %v", dir, err)
	}

	var read, noInfo, failed, withCompany, withVersion int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".dll" {
			continue
		}
		if read+noInfo >= 300 {
			break
		}

		info, err := Read(filepath.Join(dir, e.Name()))
		switch {
		case errors.Is(err, ErrNoVersionInfo):
			noInfo++
		case err != nil:
			failed++
			t.Errorf("%s: %v", e.Name(), err)
		default:
			read++
			if info.CompanyName != "" {
				withCompany++
			}
			if info.FixedFileVersion != "" && info.FixedFileVersion != "0.0.0.0" {
				withVersion++
			}
		}
	}

	t.Logf("read %d, no version info %d, errors %d", read, noInfo, failed)
	t.Logf("of those read: %d have a company, %d a usable version", withCompany, withVersion)

	if read == 0 {
		t.Fatal("extracted version info from nothing in System32, which cannot be right")
	}
	// Missing version info is legitimate; a hard error is not.
	if failed > 0 {
		t.Errorf("%d files failed to read for reasons other than absent version info", failed)
	}
	if withVersion*2 < read {
		t.Errorf("only %d of %d files yielded a version; extraction is not working properly", withVersion, read)
	}
}

func TestReadMissingFile(t *testing.T) {
	_, err := Read(filepath.Join(os.TempDir(), "swinv-does-not-exist-4f2a.dll"))
	if !errors.Is(err, ErrNoVersionInfo) {
		t.Errorf("err = %v, want ErrNoVersionInfo", err)
	}
}

func TestReadNonPEFile(t *testing.T) {
	// A text file has no version resource and must be reported as such rather
	// than producing invented values.
	path := filepath.Join(t.TempDir(), "not-a-binary.dll")
	if err := os.WriteFile(path, []byte("this is not a PE file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); !errors.Is(err, ErrNoVersionInfo) {
		t.Errorf("err = %v, want ErrNoVersionInfo", err)
	}
}
