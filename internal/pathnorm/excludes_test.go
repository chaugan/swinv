package pathnorm

import "testing"

func TestSubtreeExcludes(t *testing.T) {
	skip := SubtreeExcludes([]string{"./opt/build/**", "./snap", "**/*.iso", "./x/*.tmp"})
	for rel, want := range map[string]bool{
		"/opt/build":        true,
		"/opt/build/a/b.so": true,
		"/opt/buildx":       false,
		"/snap/core20":      true,
		"/usr/bin/sh":       false,
		"/x/a.tmp":          false, // globs inside the anchor are not subtrees
	} {
		if got := skip(rel); got != want {
			t.Errorf("skip(%q) = %v, want %v", rel, got, want)
		}
	}
	if SubtreeExcludes(nil) != nil {
		t.Error("no patterns should mean no test at all")
	}
	if SubtreeExcludes([]string{"**/*.iso"}) != nil {
		t.Error("only ./-anchored patterns are honoured, same as the symlink preflight")
	}
}
