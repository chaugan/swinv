package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// dumpStacks writes every goroutine's stack to a file in dir and returns the
// path it wrote.
//
// This exists because a scan that appears hung is very hard to diagnose
// remotely. Go dumps all stacks on SIGQUIT, and on Windows on Ctrl+Break, but
// neither is reachable for someone running a scheduled task, and Break is not
// on many laptop keyboards at all. A flag that produces the same information
// without a keystroke turns "it never finishes" into a precise answer.
func dumpStacks(dir string) (string, error) {
	// A goroutine dump for a scan with many workers can be large; grow until
	// it fits rather than truncating, since a truncated stack usually loses
	// exactly the frame that matters.
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}

	name := fmt.Sprintf("swinv-stacks-%s.txt", time.Now().UTC().Format("20060102T150405Z"))
	// O_EXCL|O_NOFOLLOW: the goroutine dump names scanned paths and internal
	// addresses, and swinv runs as root. A predictable name written with
	// O_CREATE|O_TRUNC into a shared directory lets an unprivileged user
	// pre-plant a file to capture the dump, or a symlink to redirect the
	// write onto a root-owned file. Refusing an existing path and never
	// following a symlink closes both.
	path := filepath.Join(dir, name)
	if err := writeExclusive(path, buf); err != nil {
		// Fall back to a private, unpredictable temp file: the output
		// directory may be read-only, or may be the very thing misbehaving.
		// os.CreateTemp creates with O_EXCL and a random suffix in a dir only
		// this process should be writing dumps into.
		tmpDir, mkErr := os.MkdirTemp("", "swinv-stacks-")
		if mkErr != nil {
			return "", fmt.Errorf("writing goroutine dump: %w", err)
		}
		f, cErr := os.CreateTemp(tmpDir, "stacks-*.txt")
		if cErr != nil {
			return "", fmt.Errorf("writing goroutine dump: %w", err)
		}
		defer func() { _ = f.Close() }()
		if _, wErr := f.Write(buf); wErr != nil {
			return "", fmt.Errorf("writing goroutine dump: %w", wErr)
		}
		return f.Name(), nil
	}
	return path, nil
}
