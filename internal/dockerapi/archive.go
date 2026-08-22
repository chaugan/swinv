package dockerapi

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
)

// maxArchiveBytes caps one extracted file. The container chooses its own
// filesystem contents, so a cap is the difference between reading a package
// database and letting a container decide how much memory an inventory scan
// uses.
const maxArchiveBytes = 32 << 20

// maxArchiveEntries caps how many members are walked in one response.
const maxArchiveEntries = 20000

// symlinkHops bounds how far a symlink chain is followed. /etc/os-release is a
// link to ../usr/lib/os-release on Debian, so one hop is the common case and
// the limit exists only to stop a loop.
const symlinkHops = 4

// ReadFile returns one file from a container's filesystem.
//
// This works whether or not the container is running, which is the reason it
// exists: /proc/<pid>/root needs a live process, and on Windows there is no
// /proc at all. It is the only way to see inside a stopped container, and the
// only way to see inside any container from Windows.
//
// Symlinks are followed, because the interesting paths are often links --
// /etc/os-release points at ../usr/lib/os-release on Debian, and a reader that
// stopped at the link would report a container with no operating system.
func (c *Client) ReadFile(ctx context.Context, id, filePath string) ([]byte, error) {
	seen := make(map[string]bool, symlinkHops)
	for hop := 0; hop < symlinkHops; hop++ {
		if seen[filePath] {
			return nil, fmt.Errorf("symlink loop at %s", filePath)
		}
		seen[filePath] = true

		body, err := c.archive(ctx, id, filePath)
		if err != nil {
			return nil, err
		}
		content, link, err := singleFile(body)
		if err != nil {
			return nil, err
		}
		if link == "" {
			return content, nil
		}
		// A relative link resolves against the directory holding it.
		if strings.HasPrefix(link, "/") {
			filePath = path.Clean(link)
		} else {
			filePath = path.Clean(path.Join(path.Dir(filePath), link))
		}
	}
	return nil, fmt.Errorf("too many symlinks resolving %s", filePath)
}

// ReadDir returns the regular files directly inside a directory, keyed by
// name. Used for dpkg's per-package file lists, which is a directory of
// several hundred small files and one request rather than several hundred.
func (c *Client) ReadDir(ctx context.Context, id, dirPath string) (map[string][]byte, error) {
	body, err := c.archive(ctx, id, dirPath)
	if err != nil {
		return nil, err
	}

	out := make(map[string][]byte)
	tr := tar.NewReader(bytes.NewReader(body))
	base := path.Base(strings.TrimRight(dirPath, "/"))
	for i := 0; i < maxArchiveEntries; i++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, nil // whatever was read stands; a truncated tar is not fatal
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Members are named relative to the requested directory's parent, so
		// "info/nginx.list" for a request of /var/lib/dpkg/info. Only direct
		// children are wanted.
		name := path.Clean(hdr.Name)
		rest, ok := strings.CutPrefix(name, base+"/")
		if !ok || strings.Contains(rest, "/") {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(tr, maxArchiveBytes))
		if err != nil {
			continue
		}
		out[rest] = content
	}
	return out, nil
}

// archive fetches a path as a tar stream.
func (c *Client) archive(ctx context.Context, id, filePath string) ([]byte, error) {
	endpoint := "/containers/" + url.PathEscape(id) + "/archive?path=" + url.QueryEscape(filePath)
	return c.getRaw(ctx, endpoint)
}

// singleFile pulls the one regular file out of a tar, or reports the symlink
// it found instead.
func singleFile(body []byte) (content []byte, linkTarget string, err error) {
	tr := tar.NewReader(bytes.NewReader(body))
	for i := 0; i < maxArchiveEntries; i++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, "", fmt.Errorf("no file in the archive")
		}
		if err != nil {
			return nil, "", err
		}
		switch hdr.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			return nil, hdr.Linkname, nil
		case tar.TypeReg:
			content, err := io.ReadAll(io.LimitReader(tr, maxArchiveBytes))
			return content, "", err
		}
	}
	return nil, "", fmt.Errorf("no file in the archive")
}
