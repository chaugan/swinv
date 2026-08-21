//go:build linux

package service

// Supported reports whether this platform can enumerate listening sockets.
//
// It exists so the caller can tell "nothing is listening" from "this build
// cannot look", which are the same empty Result but very different statements
// to put in a report. Windows has the equivalent data behind
// GetExtendedTcpTable; until that is written, a Windows report says nothing
// about services rather than saying there are none.
func Supported() bool { return true }
