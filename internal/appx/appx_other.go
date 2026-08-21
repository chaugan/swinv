//go:build !windows

package appx

func readPackages() ([]Package, error) { return nil, ErrUnsupportedPlatform }
func readUpdates() ([]Update, error)   { return nil, ErrUnsupportedPlatform }
