package main

import (
	"runtime"
	"testing"
)

func TestResolveParallelism(t *testing.T) {
	cpus := runtime.NumCPU()

	t.Run("explicit wins over both modes", func(t *testing.T) {
		for _, fast := range []bool{false, true} {
			if got := resolveParallelism(7, fast); got != 7 {
				t.Errorf("fast=%v: got %d, want 7", fast, got)
			}
		}
	})

	t.Run("oversubscription is allowed", func(t *testing.T) {
		want := cpus * 4
		if got := resolveParallelism(want, false); got != want {
			t.Errorf("got %d, want %d: a scan blocked on I/O may legitimately want more workers than CPUs", got, want)
		}
	})

	t.Run("fast uses every CPU", func(t *testing.T) {
		if got := resolveParallelism(0, true); got != cpus {
			t.Errorf("got %d, want %d", got, cpus)
		}
	})

	t.Run("background uses a quarter, never zero", func(t *testing.T) {
		got := resolveParallelism(0, false)
		if got < 1 {
			t.Fatalf("got %d: a worker count below 1 would stall the scan entirely", got)
		}
		if want := cpus / 4; want > 0 && got != want {
			t.Errorf("got %d, want %d", got, want)
		}
		if got > cpus {
			t.Errorf("got %d, want no more than %d: background mode must never exceed --fast", got, cpus)
		}
	})
}
