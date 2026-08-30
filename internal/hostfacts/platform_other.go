//go:build !windows

package hostfacts

import (
	"os"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// platformFacts has nothing to add away from Windows: /etc/os-release,
// /etc/machine-id and /sys/class/dmi have already been read by the time this
// is called, and they are the authoritative answer here.
func platformFacts(*model.Host, bool) {}

// refineInterfaceType names the interface kinds only the OS can tell apart,
// beyond what the interface flags say. On Linux that is /sys/class/net:
// a directory appears there exactly when the interface is that kind, so the
// checks are existence tests, cheap and racing nothing that matters - a
// worst case is one scan classifying an interface the previous scan named
// differently, which is a fact about the machine changing, not about the
// read.
//
// An empty return means "no refinement", and the caller falls back to the
// flag-based classification. Away from Linux this file still builds, and the
// sysfs paths simply do not exist, so the reads miss and the fallback runs.
func refineInterfaceType(name string) string {
	if strings.ContainsAny(name, "/\\") {
		return "" // a name is a bare interface name; never a path prefix
	}
	sys := "/sys/class/net/" + name
	for _, kind := range []struct{ dir, label string }{
		{"wireless", "wireless"}, // also where the /proc wireless extensions lived
		{"phy80211", "wireless"}, // mac80211 devices expose this instead
		{"bridge", "bridge"},
		{"bonding", "bond"},
	} {
		if fi, err := os.Stat(sys + "/" + kind.dir); err == nil && fi.IsDir() {
			return kind.label
		}
	}
	return ""
}
