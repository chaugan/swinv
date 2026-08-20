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
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		// Fall back to the temp directory: the output directory may be
		// read-only, or may be the very thing that is misbehaving.
		path = filepath.Join(os.TempDir(), name)
		if err2 := os.WriteFile(path, buf, 0o600); err2 != nil {
			return "", fmt.Errorf("writing goroutine dump: %w", err)
		}
	}
	return path, nil
}
