package pathnorm

import "strings"

// SubtreeExcludes turns the operator's exclusion patterns into a subtree
// test for the walks that are not Syft's: the SUID walk and the ELF walk.
//
// Only the ./-anchored form is honoured ("./opt/build/**", "./opt/build"),
// the same rule the symlink preflight applies and for the same reason: a
// */ or **/ pattern needs full glob matching against every path, and the
// walks exist to be cheap. Over-walking is the safe direction to be wrong
// in - except that it stopped being cheap the day a CI runner's /opt held
// a toolchain cache six minutes deep, which is why this exists at all.
//
// The returned test takes a report-relative path ("/opt/build/x") and
// reports whether an exclusion covers it.
func SubtreeExcludes(patterns []string) func(rel string) bool {
	var subtrees []string
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		rest, ok := strings.CutPrefix(p, "./")
		if !ok {
			continue
		}
		rest = strings.TrimSuffix(rest, "/**")
		rest = strings.TrimSuffix(rest, "/")
		if rest == "" || strings.ContainsAny(rest, "*?[") {
			continue // a glob inside the anchor is not a subtree
		}
		subtrees = append(subtrees, "/"+rest)
	}
	if len(subtrees) == 0 {
		return nil
	}
	return func(rel string) bool {
		for _, s := range subtrees {
			if rel == s || strings.HasPrefix(rel, s+"/") {
				return true
			}
		}
		return false
	}
}
