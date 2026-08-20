//go:build !windows

package usn

import "context"

func enumerate(context.Context, Options) (*Result, error) { return nil, ErrUnsupportedPlatform }
