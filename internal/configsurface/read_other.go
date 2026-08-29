//go:build !unix

package configsurface

import "os"

func fileUID(os.FileInfo) (uint32, bool) { return 0, false }

func suidOwner(os.FileInfo) (uint32, bool) { return 0, false }

func openNonBlocking(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- path under the scan root; checked on the fd
}
