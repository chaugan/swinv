//go:build !windows

package arp

func read() ([]Entry, error) { return nil, ErrUnsupportedPlatform }
