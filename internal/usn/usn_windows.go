//go:build windows

package usn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// FSCTL_ENUM_USN_DATA, from winioctl.h. It enumerates MFT records
	// directly and, unlike FSCTL_READ_USN_JOURNAL, does not require the change
	// journal to be active -- which matters because the journal is not enabled
	// on every volume and enabling it would be a modification to the machine.
	fsctlEnumUsnData = 0x000900B3

	// bufferSize trades syscalls against memory. A megabyte holds a few
	// thousand records, so a million-file volume costs a few hundred calls
	// rather than a few hundred thousand.
	bufferSize = 1 << 20
)

// mftEnumDataV0 is MFT_ENUM_DATA_V0. All fields are 8 bytes, so Go's layout
// matches the packed C struct and it can be passed to the kernel directly --
// unlike USN_RECORD_V2, which is why records are parsed by offset instead.
type mftEnumDataV0 struct {
	StartFileReferenceNumber uint64
	LowUsn                   int64
	HighUsn                  int64
}

func enumerate(ctx context.Context, opts Options) (*Result, error) {
	volume, err := normalizeVolume(opts.Volume)
	if err != nil {
		return nil, err
	}
	if err := requireNTFS(volume); err != nil {
		return nil, err
	}

	handle, err := openVolume(volume)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	keep := opts.Keep
	if keep == nil {
		keep = func(string, bool, uint32) bool { return true }
	}

	var (
		dirs       = make(map[uint64]dirEntry)
		candidates []candidate
		records    int
	)

	in := mftEnumDataV0{LowUsn: 0, HighUsn: math.MaxInt64}
	out := make([]byte, bufferSize)

	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("usn: enumerating %s: %w", volume, err)
		}

		var returned uint32
		err := windows.DeviceIoControl(handle, fsctlEnumUsnData,
			(*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)),
			&out[0], uint32(len(out)), &returned, nil)
		if err != nil {
			if errors.Is(err, windows.ERROR_HANDLE_EOF) {
				break
			}
			return nil, fmt.Errorf("usn: enumerating the MFT of %s: %w", volume, err)
		}

		// The first eight bytes are the reference to resume from; anything
		// less means the kernel returned a cursor and no records.
		if returned <= 8 {
			break
		}
		in.StartFileReferenceNumber = binary.LittleEndian.Uint64(out[:8])

		err = parseRecords(out[8:returned], func(r rawRecord) error {
			records++
			isDir := r.Attributes&attrDirectory != 0

			// Every directory is retained whether or not the caller wants it
			// in the output, because a file's path cannot be reconstructed
			// without its ancestors. Directories are a small fraction of a
			// volume, so this is the cheap half of the memory cost.
			if isDir {
				dirs[r.FileRef] = dirEntry{name: r.Name, parent: r.ParentRef}
			}

			if !keep(r.Name, isDir, r.Attributes) {
				return nil
			}
			candidates = append(candidates, candidate{
				name:       r.Name,
				fileRef:    r.FileRef,
				parentRef:  r.ParentRef,
				attributes: r.Attributes,
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return buildResult(volume, dirs, candidates, records), nil
}

// requireNTFS rejects a volume with no Master File Table before any handle is
// opened. ReFS, FAT32 and exFAT all land here.
func requireNTFS(volume string) error {
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return fmt.Errorf("usn: %s: %w", volume, err)
	}

	fsName := make([]uint16, windows.MAX_PATH+1)
	err = windows.GetVolumeInformation(root, nil, 0, nil, nil, nil, &fsName[0], uint32(len(fsName)))
	if err != nil {
		return fmt.Errorf("usn: reading the filesystem type of %s: %w", volume, err)
	}

	if name := windows.UTF16ToString(fsName); !strings.EqualFold(name, "NTFS") {
		return fmt.Errorf("%w: %s is %s", ErrNotNTFS, volume, name)
	}
	return nil
}

// openVolume opens the raw volume device, which is what FSCTL_ENUM_USN_DATA
// operates on.
func openVolume(volume string) (windows.Handle, error) {
	device, err := windows.UTF16PtrFromString(`\\.\` + volume)
	if err != nil {
		return 0, fmt.Errorf("usn: %s: %w", volume, err)
	}

	// FILE_SHARE_READ|WRITE because the volume is in use by everything else on
	// the machine and an inventory must never lock it. GENERIC_READ alone is
	// enough for this control code.
	h, err := windows.CreateFile(device,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return 0, fmt.Errorf("%w: opening %s", ErrNotElevated, volume)
		}
		return 0, fmt.Errorf("usn: opening volume %s: %w", volume, err)
	}
	return h, nil
}
