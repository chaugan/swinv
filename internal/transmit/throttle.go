package transmit

import (
	"context"
	"io"
	"time"
)

// throttledReader paces reads to a byte rate, for metered and satellite links
// where the constraint is the rate rather than the total. The gzip work
// already cut the total about 9:1; this bounds what is left.
type throttledReader struct {
	r   io.Reader
	bps int64
	ctx context.Context

	start time.Time
	sent  int64
}

func (t *throttledReader) Read(p []byte) (int, error) {
	if t.start.IsZero() {
		t.start = time.Now()
	}
	// Small chunks keep the pacing smooth; a tenth of a second of budget per
	// read means the sleep below is never longer than ~100ms per call.
	chunk := int(t.bps / 10)
	if chunk < 1 {
		chunk = 1
	}
	if len(p) > chunk {
		p = p[:chunk]
	}
	n, err := t.r.Read(p)
	t.sent += int64(n)

	// Sleep until the bytes sent so far are allowed by the elapsed time.
	due := time.Duration(t.sent) * time.Second / time.Duration(t.bps)
	if wait := due - time.Since(t.start); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-t.ctx.Done():
			return n, t.ctx.Err()
		case <-timer.C:
		}
	}
	return n, err
}
