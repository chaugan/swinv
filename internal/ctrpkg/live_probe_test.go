package ctrpkg

import (
	"os"
	"testing"
)

// A live probe against a real container, driven by an environment variable so
// it is a no-op everywhere except where someone deliberately points it at one.
func TestLiveProbe(t *testing.T) {
	root := os.Getenv("SWINV_PROBE_ROOT")
	if root == "" {
		t.Skip("set SWINV_PROBE_ROOT=/proc/<pid>/root and SWINV_PROBE_EXE to run")
	}
	rel := ReadRelease(root)
	t.Logf("release: %+v", rel)

	exes := []string{os.Getenv("SWINV_PROBE_EXE")}
	owners := Probe(root, exes, rel)
	for _, e := range exes {
		if o, ok := owners[e]; ok {
			t.Logf("%s -> %s@%s (%s) %s", e, o.Name, o.Version, o.Type, o.PURL)
		} else {
			t.Logf("%s -> no package owns it", e)
		}
	}
}
