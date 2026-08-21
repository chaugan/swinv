//go:build !windows

package hostfacts

import "github.com/chaugan/swinv/internal/model"

// platformFacts has nothing to add away from Windows: /etc/os-release,
// /etc/machine-id and /sys/class/dmi have already been read by the time this
// is called, and they are the authoritative answer here.
func platformFacts(*model.Host, bool) {}
