//go:build !linux

package service

import "github.com/chaugan/swinv/internal/model"

// EnrichContainers has nothing to read away from Linux: the container's
// filesystem is reached through /proc/<pid>/root, which only exists here.
func EnrichContainers(string, []Container, bool) []model.Container { return nil }
