//go:build !linux

package service

import "context"

// collect has nothing to read away from Linux: this is built entirely on
// /proc. Returning an empty result rather than an error is deliberate -- the
// caller has not done anything wrong by asking, and an inventory that refuses
// to be produced because one optional section is unavailable is worse than one
// that reports what it can.
func collect(context.Context, string) (*Result, error) { return &Result{}, nil }
