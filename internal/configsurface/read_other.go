//go:build !unix

package configsurface

import "os"

func fileUID(os.FileInfo) (uint32, bool) { return 0, false }

func suidOwner(os.FileInfo) (uint32, bool) { return 0, false }
