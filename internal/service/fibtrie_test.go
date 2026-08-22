package service

import (
	"reflect"
	"testing"
)

// Real output from a container's namespace on the development host.
const fibTrieSample = `Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     |-- 172.25.0.1
        /32 universe UNICAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.25.0.0/16 2 0 2
        +-- 172.25.0.0/30 2 0 2
           |-- 172.25.0.0
              /16 link UNICAST
           |-- 172.25.0.2
              /32 host LOCAL
        |-- 172.25.255.255
           /32 link BROADCAST
`

func TestParseFibTrieLocal(t *testing.T) {
	got := parseFibTrieLocal(fibTrieSample)
	want := []string{"172.25.0.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseFibTrieLocal = %v, want %v", got, want)
	}
}

// A broadcast address answers nothing and joins nothing; taking it would map a
// published port to the wrong container.
func TestParseFibTrieLocalIgnoresBroadcastAndRoutes(t *testing.T) {
	for _, unwanted := range []string{"172.25.255.255", "172.25.0.0", "172.25.0.1", "127.0.0.1", "0.0.0.0"} {
		for _, got := range parseFibTrieLocal(fibTrieSample) {
			if got == unwanted {
				t.Errorf("parseFibTrieLocal returned %q", unwanted)
			}
		}
	}
}

func TestParseFibTrieLocalEmpty(t *testing.T) {
	if got := parseFibTrieLocal(""); got != nil {
		t.Errorf("parseFibTrieLocal(\"\") = %v, want nil", got)
	}
}
