package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAnInventoryFileIsNeverObservedPartial is §4.4.
//
// The reported failure was <hostname>.ndjson written, then written again six
// seconds later, so any monitor reading the first copy saw it truncate
// mid-read. This runs two scans over one fixed output name while a reader
// hammers the file, and demands that every observation is either "not there"
// or a complete document -- never a prefix of one.
func TestAnInventoryFileIsNeverObservedPartial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture is a Linux rootfs")
	}
	out := t.TempDir()
	root, err := filepath.Abs("../../testdata/rootfs")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(out, "fixed.json")
	ndjson := filepath.Join(out, "fixed.ndjson")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var partial []string
	var reads int

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, path := range []string{target, ndjson} {
				raw, err := os.ReadFile(path) //#nosec G304 -- test-controlled path
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						continue
					}
					mu.Lock()
					partial = append(partial, path+": "+err.Error())
					mu.Unlock()
					continue
				}
				mu.Lock()
				reads++
				mu.Unlock()
				if problem := completeDocument(path, raw); problem != "" {
					mu.Lock()
					partial = append(partial, problem)
					mu.Unlock()
				}
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	for pass := 0; pass < 2; pass++ {
		var stdout, stderr bytes.Buffer
		code := run([]string{
			"--root", root, "--out", out,
			"--format", "json,ndjson", "--name", "fixed", "--output-mode", "overwrite",
			"--latest-symlink=false", "--heartbeat", "--force-full",
			"--timeout", "5m", "--quiet",
		}, &stdout, &stderr)
		if code != exitOK && code != exitIncomplete {
			t.Fatalf("pass %d: exit = %d\nstderr: %s", pass, code, stderr.String())
		}
	}

	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if reads == 0 {
		t.Fatal("the reader never saw either file, so this proves nothing")
	}
	if len(partial) > 0 {
		t.Errorf("%d of %d reads observed a partial file:\n  %s",
			len(partial), reads, strings.Join(partial[:min(len(partial), 5)], "\n  "))
	}

	// And nothing is left staged next to the finished files.
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("a staging file survived: %s", e.Name())
		}
	}
}

// completeDocument returns a description of what is wrong with raw, or "" if
// it is whole. An empty file counts as partial: the failure mode being guarded
// is a reader catching a target mid-truncation.
func completeDocument(path string, raw []byte) string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return path + ": read an empty file"
	}
	if strings.HasSuffix(path, ".ndjson") {
		for i, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			var probe map[string]any
			if err := json.Unmarshal([]byte(line), &probe); err != nil {
				return path + ": line " + itoa(i+1) + " is truncated: " + err.Error()
			}
		}
		return ""
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return path + ": truncated JSON: " + err.Error()
	}
	if _, ok := doc["components"]; !ok {
		return path + ": complete JSON with no components key"
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
