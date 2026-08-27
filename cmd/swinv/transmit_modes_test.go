package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func mustFailParse(t *testing.T, args ...string) error {
	t.Helper()
	_, code, err := parseFlags(args, io.Discard, new(bytes.Buffer))
	if err == nil {
		t.Fatalf("%v was accepted", args)
	}
	if code != exitUsage {
		t.Fatalf("%v: exit %d, want %d", args, code, exitUsage)
	}
	return err
}

func TestNewTransmitFlagsRequireTransmit(t *testing.T) {
	for _, args := range [][]string{
		{"--transmit-pin", "AAAA"},
		{"--transmit-check"},
		{"--transmit-only"},
		{"--transmit-from", "x.ndjson"},
		{"--transmit-rate-limit", "256KiB"},
		{"--transmit-key-passphrase-file", "p"},
	} {
		err := mustFailParse(t, args...)
		if !strings.Contains(err.Error(), "--transmit") {
			t.Errorf("%v: error does not name --transmit: %v", args, err)
		}
	}
}

func TestPinAndInsecureAreMutuallyExclusive(t *testing.T) {
	err := mustFailParse(t, "--transmit", "https://x/api/v1",
		"--transmit-pin", "AAAA", "--transmit-insecure")
	if !strings.Contains(err.Error(), "contradict") {
		t.Errorf("error does not explain the contradiction: %v", err)
	}
}

func TestTransmitModeConflicts(t *testing.T) {
	mustFailParse(t, "--transmit", "https://x/api/v1", "--transmit-check", "--transmit-only")
	mustFailParse(t, "--transmit", "https://x/api/v1", "--transmit-only", "--transmit-from", "a.ndjson")
	mustFailParse(t, "--transmit", "https://x/api/v1", "--transmit-tls-min", "1.1")
	mustFailParse(t, "--transmit", "https://x/api/v1", "--transmit-compress", "sometimes")
}

func TestTransmitRateLimitParses(t *testing.T) {
	cfg, _, err := parseFlags([]string{"--transmit", "https://x/api/v1",
		"--transmit-rate-limit", "256KiB"}, io.Discard, new(bytes.Buffer))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.transmitRateLimitN != 256<<10 {
		t.Errorf("rate = %d, want %d", cfg.transmitRateLimitN, 256<<10)
	}
}

// The manifest validation for --transmit-from is the server's contract run
// locally: refuse the file whose counts disagree with its contents before a
// byte leaves the machine.
func TestReadNDJSONManifestAgrees(t *testing.T) {
	stream := `{"record_type":"heartbeat","scan_id":"s1","hostname":"web01","counts":{"component":2,"exposure":1}}
{"name":"bash","version":"5.2"}
{"name":"curl","version":"8.5"}
{"record_type":"exposure","port":22}
`
	m, counted, err := readNDJSONManifest(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if m.ScanID != "s1" || m.Hostname != "web01" {
		t.Errorf("manifest = %+v", m)
	}
	if counted["component"] != 2 || counted["exposure"] != 1 {
		t.Errorf("counted = %v", counted)
	}
}

func TestReadNDJSONManifestRefusesAFileWithoutOne(t *testing.T) {
	_, _, err := readNDJSONManifest(strings.NewReader(`{"name":"bash","version":"5.2"}` + "\n"))
	if err == nil {
		t.Fatal("a file with no manifest was accepted")
	}
	if !strings.Contains(err.Error(), "--heartbeat") {
		t.Errorf("the error does not say how to produce a manifest: %v", err)
	}
}
