// Package configsurface collects the host's persistence and privilege
// configuration: cron jobs, systemd timers and services, SUID binaries,
// scheduled tasks and autoruns.
//
// Everything here is a local read - no execution, no probing, no network -
// which preserves the property that makes the collector deployable in OT,
// medical and air-gapped estates. A CVE mapping says "you have a defect that
// enables this technique"; this says "this technique has a surface here";
// neither says "you are compromised". Keeping those claims apart is the
// consumer's job, and keeping the facts collectable is this package's.
package configsurface

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// Scope values, following the --elf-scope precedent: the default covers the
// cheap, high-signal set; the exhaustive walk is opt-in; off is off.
const (
	ScopeStandard = "standard"
	ScopeAll      = "all"
	ScopeOff      = "off"
)

// Options configures one collection.
type Options struct {
	// Root is the tree to read, "/" for the running host. Everything is
	// resolved under it, so an image mounted at --root is described as
	// itself rather than as the machine doing the scanning.
	Root string

	// Scope is ScopeStandard, ScopeAll or ScopeOff. Standard walks the same
	// binary directories the ELF probe walks for SUID bits; all walks the
	// whole tree, which is the expensive part.
	Scope string

	// IncludeCommands keeps full command lines. Off under
	// --no-service-command: command lines carry passwords and tokens, and
	// an inventory file is usually copied somewhere else. Executable paths
	// are kept either way - a path is joinable and carries no secrets.
	IncludeCommands bool

	// Excludes are the operator's --exclude patterns. The SUID walk honours
	// the ./-anchored subtree form, the same rule the symlink preflight
	// applies; the fixed-path readers (cron, systemd) are not walks and are
	// unaffected. This stopped being optional when a CI runner's /opt held
	// a toolchain cache that took the walk six minutes to lstat through -
	// while the run's own command line said --exclude './opt/**' the whole
	// time.
	Excludes []string
}

// ValidateScope rejects a scope the collector does not have.
func ValidateScope(s string) error {
	switch s {
	case ScopeStandard, ScopeAll, ScopeOff:
		return nil
	}
	return fmt.Errorf("--config-scope must be standard, all or off, got %q", s)
}

// ExecutablePaths lists the executables the entries name, for the package
// ownership probe - the same join the listening services use, so a cron job
// resolves to the package that installed its program, and an entry with no
// owner stays visibly unowned.
func ExecutablePaths(entries []model.ConfigEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if e.Executable == "" || !strings.HasPrefix(e.Executable, "/") || seen[e.Executable] {
			continue
		}
		seen[e.Executable] = true
		out = append(out, e.Executable)
	}
	return out
}

// AttachOwners fills each entry's PURL from the ownership probe's answers,
// the same map the listening services join against. The first owner wins;
// a file two packages both claim is a packaging bug this record is not the
// place to litigate.
func AttachOwners(entries []model.ConfigEntry, owners map[string][]string) {
	for i := range entries {
		if entries[i].PURL != "" || entries[i].Executable == "" {
			continue
		}
		if o := owners[entries[i].Executable]; len(o) > 0 {
			entries[i].PURL = o[0]
		}
	}
}

// firstExecutable extracts the program from a command line: environment
// assignments are skipped, and only an absolute path is worth recording -
// a bare name depends on a PATH nobody recorded.
func firstExecutable(command string) string {
	for _, tok := range strings.Fields(command) {
		if strings.Contains(tok, "=") && !strings.HasPrefix(tok, "/") {
			continue // VAR=value prefix
		}
		tok = strings.TrimLeft(tok, "@-:+!") // systemd ExecStart prefixes
		if strings.HasPrefix(tok, "/") {
			return tok
		}
		return ""
	}
	return ""
}

// markWorldWritable stats the entry's executable under root and records the
// joinable half of "a root job anyone can edit". A stat failure records
// nothing: absence of the bit must never be manufactured from absence of
// the file.
func markWorldWritable(root string, e *model.ConfigEntry) {
	if e.Executable == "" {
		return
	}
	fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(e.Executable)))
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	if fi.Mode().Perm()&0o002 != 0 {
		e.WorldWritable = true
		e.Evidence = append(e.Evidence,
			fmt.Sprintf("%s is world-writable (mode %04o)", e.Executable, fi.Mode().Perm()))
	}
}
