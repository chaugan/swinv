package main

import (
	"fmt"
	"math"
	"runtime/debug"
	"strconv"
	"strings"
)

// sizeUnits maps a size suffix to its multiplier. Both the IEC ("MiB") and the
// common shorthand ("MB", "M") spellings are accepted and both mean 1024-based
// units, because that is what everyone actually means when sizing a process.
var sizeUnits = []struct {
	suffix string
	mult   int64
}{
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"TIB", 1 << 40},
	{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30}, {"TB", 1 << 40},
	{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"T", 1 << 40},
	{"B", 1},
}

// parseSize converts a human size such as "512MiB" or "2G" into bytes.
func parseSize(s string) (int64, error) {
	raw := strings.ToUpper(strings.TrimSpace(s))
	if raw == "" {
		return 0, fmt.Errorf("empty size")
	}
	for _, u := range sizeUnits {
		if !strings.HasSuffix(raw, u.suffix) {
			continue
		}
		numPart := strings.TrimSpace(strings.TrimSuffix(raw, u.suffix))
		if numPart == "" {
			return 0, fmt.Errorf("missing number in size %q", s)
		}
		value, err := strconv.ParseFloat(numPart, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid size %q", s)
		}
		if value <= 0 {
			return 0, fmt.Errorf("size must be positive, got %q", s)
		}
		bytes := value * float64(u.mult)
		if bytes > math.MaxInt64 {
			return 0, fmt.Errorf("size %q is too large", s)
		}
		return int64(bytes), nil
	}
	// A bare number is bytes.
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid size %q (want something like 512MiB or 2GiB)", s)
	}
	return value, nil
}

// applyMemoryLimit sets Go's soft memory limit for the process.
//
// This is the one lever that meaningfully bounds swinv's peak memory. Most of
// the footprint is Syft's in-memory index of every path it walked, and Go's
// default GOGC=100 lets the heap grow to roughly twice the live set before
// collecting. A soft limit makes the collector work proportionally harder as
// the limit is approached, trading CPU for resident memory.
//
// It is a SOFT limit by design: if the genuinely-live data exceeds it, the
// process still allocates rather than failing, because returning a truncated
// inventory would be worse than using more memory. It therefore reduces peak
// RSS but cannot guarantee a ceiling - say so to the caller rather than imply
// a hard bound.
func applyMemoryLimit(bytes int64) {
	debug.SetMemoryLimit(bytes)
}
