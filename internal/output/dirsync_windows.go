//go:build windows

package output

// syncDir is a no-op on Windows, where flushing a directory is not a supported
// operation: FlushFileBuffers - which os.File.Sync calls - rejects a directory
// handle with ERROR_INVALID_FUNCTION. Returning that as an error would fail
// every write on the platform.
//
// Durability does not suffer. The temp file is still fsynced before the
// rename, and MoveFileEx with MOVEFILE_REPLACE_EXISTING, which os.Rename uses,
// is atomic on NTFS and journals the directory entry itself.
func syncDir(string) error { return nil }
