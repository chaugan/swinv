//go:build !windows

package main

// secureOutputDir is a no-op off Windows: POSIX modes on the directory and
// files (dirPerm/perm from --perm) already govern access, and MkdirAll honours
// them. The Windows build has no inherited-ACL problem to solve here.
func secureOutputDir(string) error { return nil }
