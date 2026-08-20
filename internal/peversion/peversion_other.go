//go:build !windows

package peversion

func read(string) (Info, error) { return Info{}, ErrUnsupportedPlatform }
