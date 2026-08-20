//go:build !windows

package wincollect

import "context"

func collect(context.Context, Options) (*Result, error) { return nil, ErrUnsupportedPlatform }
