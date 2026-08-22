//go:build !linux && !windows

package service

// Supported reports whether this platform can enumerate listening sockets.
// See the Linux and Windows implementations for why the distinction is worth
// a function.
func Supported() bool { return false }
