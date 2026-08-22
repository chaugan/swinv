package dockerapi

import (
	"context"
	"path"
	"strings"
)

// ContainerSource reads a container's filesystem through the runtime.
//
// It satisfies ctrpkg.Source without importing it, so the dependency runs one
// way: the package that knows about containers knows nothing about package
// databases.
type ContainerSource struct {
	client *Client
	ctx    context.Context
	id     string
}

// Source returns a reader for one container's filesystem. It works whether or
// not the container is running.
func (c *Client) Source(ctx context.Context, id string) *ContainerSource {
	return &ContainerSource{client: c, ctx: ctx, id: id}
}

func (s *ContainerSource) ReadFile(p string) ([]byte, error) {
	return s.client.ReadFile(s.ctx, s.id, p)
}

func (s *ContainerSource) ReadDir(p string) (map[string][]byte, error) {
	return s.client.ReadDir(s.ctx, s.id, p)
}

// IsSymlink reports whether a top-level directory is a symlink.
//
// Asked by requesting the path itself: the runtime returns the link rather
// than what it points at, so a symlink shows up as a member with a link target
// and a real directory does not.
func (s *ContainerSource) IsSymlink(p string) bool {
	body, err := s.client.archive(s.ctx, s.id, "/"+strings.TrimPrefix(path.Clean(p), "/"))
	if err != nil {
		return false
	}
	_, link, err := singleFile(body)
	return err == nil && link != ""
}
