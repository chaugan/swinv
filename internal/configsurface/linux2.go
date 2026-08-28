//go:build linux

package configsurface

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// This file is the second slice of the Linux configuration surface (#13):
// sudo rules, SSH authorized keys, accounts, kernel modules, ld.so.preload
// and shell init. Every one is a local read, and every record carries the
// ATT&CK technique its mechanism is the surface for. Collecting a row is not
// a finding; the finding is the join a consumer makes over it.

func collectLinuxExtras(root string, includeCommands bool) []model.ConfigEntry {
	var out []model.ConfigEntry
	out = append(out, collectSudo(root, includeCommands)...)
	out = append(out, collectSSHKeys(root, includeCommands)...)
	out = append(out, collectAccounts(root)...)
	out = append(out, collectKernelModules(root)...)
	out = append(out, collectPreload(root)...)
	out = append(out, collectShellInit(root, includeCommands)...)
	return out
}

// collectSudo reads sudoers and the drop-in directory. The interesting rows
// are the ones a consumer ranks: NOPASSWD (a privilege grant with no
// authentication) and ALL=(ALL) breadth. The rule text is the evidence.
func collectSudo(root string, includeCommands bool) []model.ConfigEntry {
	files := []string{"/etc/sudoers"}
	if names, err := os.ReadDir(under(root, "/etc/sudoers.d")); err == nil {
		for _, de := range names {
			if !de.IsDir() && !strings.HasPrefix(de.Name(), ".") {
				files = append(files, "/etc/sudoers.d/"+de.Name())
			}
		}
	}
	var out []model.ConfigEntry
	for _, f := range files {
		raw, ok := readCapped(under(root, f))
		if !ok {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
				continue
			}
			// A user/group specification: "who host=(runas) commands".
			if !strings.Contains(line, "=") {
				continue
			}
			who, _, _ := strings.Cut(line, " ")
			e := model.ConfigEntry{
				Kind:   model.ConfigKindSudoRule,
				Name:   strings.TrimSpace(who),
				Path:   f,
				User:   strings.TrimSpace(who),
				Attack: "T1548.003",
			}
			if includeCommands {
				var ev []string
				if strings.Contains(line, "NOPASSWD") {
					ev = append(ev, "grants sudo with NOPASSWD (no authentication)")
				}
				if strings.Contains(strings.ReplaceAll(line, " ", ""), "=(ALL") ||
					strings.Contains(line, "ALL=(ALL") || strings.HasSuffix(line, "ALL") {
					ev = append(ev, "broad grant (ALL)")
				}
				e.Evidence = ev
			}
			out = append(out, e)
		}
	}
	return out
}

// collectSSHKeys reads each account's authorized_keys. An entry is one
// standing credential; the interesting join is a key on an account with no
// password and no login shell.
func collectSSHKeys(root string, includeCommands bool) []model.ConfigEntry {
	var out []model.ConfigEntry
	for _, acct := range accountHomeList(root) {
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := filepath.Join(acct.home, ".ssh", name)
			// Ownership-gated: the file lives in a directory the account owns,
			// and a symlink to a root-only file (/root/.aws/credentials) would
			// otherwise be read by the root collector and its contents placed
			// in a report the attacker can read back. A real key file is owned
			// by its own account; the gate refuses anything that resolves to a
			// differently-owned file.
			raw, ok := readOwnedByCapped(under(root, p), acct.uid)
			if !ok {
				continue
			}
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				e := model.ConfigEntry{
					Kind:     model.ConfigKindSSHKey,
					Path:     p,
					User:     acct.user,
					Attack:   "T1098.004",
					Evidence: []string{sshKeyType(line)},
				}
				// The trailing "user@host" comment is free text an operator
				// may have put anything in; it rides the same redaction switch
				// as command lines, which can carry secrets.
				if includeCommands {
					e.Name = sshKeyComment(line)
				}
				out = append(out, e)
			}
		}
	}
	return out
}

// collectAccounts reads /etc/passwd. The rows worth a record are the ones a
// consumer ranks: uid 0 (root-equivalent), and login-capable accounts.
func collectAccounts(root string) []model.ConfigEntry {
	raw, ok := readCapped(under(root, "/etc/passwd"))
	if !ok {
		return nil
	}
	var out []model.ConfigEntry
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		name, uid, shell := fields[0], fields[2], fields[6]
		nologin := strings.Contains(shell, "nologin") || strings.Contains(shell, "false") || shell == ""
		var ev []string
		if uid == "0" {
			ev = append(ev, "uid 0: root-equivalent")
		}
		if !nologin {
			ev = append(ev, "login shell "+shell)
		}
		// Only the accounts that matter: uid 0, or a real login shell.
		if uid != "0" && nologin {
			continue
		}
		out = append(out, model.ConfigEntry{
			Kind:     model.ConfigKindAccount,
			Name:     name,
			Path:     "/etc/passwd",
			User:     name,
			Attack:   pickAttack(uid == "0"),
			Evidence: ev,
		})
	}
	return out
}

func pickAttack(uid0 bool) string {
	if uid0 {
		return "T1078" // valid accounts / privileged
	}
	return "T1136" // account existence
}

// collectKernelModules reads the loaded set and the configured-to-load set.
// A module loaded from outside the module tree is the joinable weakness.
func collectKernelModules(root string) []model.ConfigEntry {
	var out []model.ConfigEntry
	if raw, ok := readCapped(under(root, "/proc/modules")); ok {
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			out = append(out, model.ConfigEntry{
				Kind:     model.ConfigKindKernelModule,
				Name:     f[0],
				Path:     "/proc/modules",
				Attack:   "T1547.006",
				Evidence: []string{"loaded"},
			})
		}
	}
	if names, err := os.ReadDir(under(root, "/etc/modules-load.d")); err == nil {
		for _, de := range names {
			if de.IsDir() {
				continue
			}
			p := "/etc/modules-load.d/" + de.Name()
			raw, ok := readCapped(under(root, p))
			if !ok {
				continue
			}
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				out = append(out, model.ConfigEntry{
					Kind:     model.ConfigKindKernelModule,
					Name:     line,
					Path:     p,
					Attack:   "T1547.006",
					Evidence: []string{"configured to load at boot"},
				})
			}
		}
	}
	return out
}

// collectPreload reads /etc/ld.so.preload: every listener on the machine
// loads whatever it names, before its own libraries. A near-universal
// interposition point, and empty on a healthy host.
func collectPreload(root string) []model.ConfigEntry {
	raw, ok := readCapped(under(root, "/etc/ld.so.preload"))
	if !ok {
		return nil
	}
	var out []model.ConfigEntry
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, model.ConfigEntry{
			Kind:       model.ConfigKindPreload,
			Name:       filepath.Base(line),
			Path:       "/etc/ld.so.preload",
			Executable: line,
			Attack:     "T1574.006",
			Evidence:   []string{"preloaded into every dynamically linked process"},
		})
	}
	return out
}

// collectShellInit records the system-wide shell entry points. These run for
// every interactive login, which is why they are a persistence surface.
func collectShellInit(root string, includeCommands bool) []model.ConfigEntry {
	var out []model.ConfigEntry
	if names, err := os.ReadDir(under(root, "/etc/profile.d")); err == nil {
		for _, de := range names {
			if de.IsDir() {
				continue
			}
			p := "/etc/profile.d/" + de.Name()
			out = append(out, model.ConfigEntry{
				Kind:       model.ConfigKindShellInit,
				Name:       de.Name(),
				Path:       p,
				Executable: p,
				Attack:     "T1546.004",
			})
		}
	}
	return out
}

// --- small helpers ---------------------------------------------------------

// acctHome is one account's user name, uid and home directory from /etc/passwd.
type acctHome struct {
	user string
	uid  uint32
	home string
}

// accountHomeList reads /etc/passwd for the home directories and uids the
// ssh-key collector needs. The uid is the ownership the key file must match.
func accountHomeList(root string) []acctHome {
	raw, ok := readCapped(under(root, "/etc/passwd"))
	if !ok {
		return nil
	}
	var out []acctHome
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 6 || f[5] == "" {
			continue
		}
		uid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		out = append(out, acctHome{user: f[0], uid: uint32(uid), home: f[5]})
	}
	return out
}

func sshKeyType(line string) string {
	f := strings.Fields(line)
	for _, tok := range f {
		if strings.HasPrefix(tok, "ssh-") || strings.HasPrefix(tok, "ecdsa-") ||
			strings.HasPrefix(tok, "sk-") {
			return tok
		}
	}
	return "authorized key"
}

func sshKeyComment(line string) string {
	f := strings.Fields(line)
	if len(f) >= 3 {
		return strings.Join(f[2:], " ")
	}
	if len(f) == 2 {
		return "unnamed key"
	}
	return "key"
}
