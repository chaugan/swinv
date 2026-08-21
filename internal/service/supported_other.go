//go:build !linux

package service

// Supported reports whether this platform can enumerate listening sockets.
// See the Linux implementation for why the distinction is worth a function.
func Supported() bool { return false }
