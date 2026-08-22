//go:build linux

package service

import (
	"testing"

	"github.com/chaugan/swinv/internal/model"
)

// nginx's master and its workers all hold the same inherited socket. Reporting
// nine services misstates both what is running and how much of it, and repeats
// the same identity nine times in every downstream count.
func TestCollapseWorkers(t *testing.T) {
	var services []model.Service
	for _, pid := range []int{412, 400, 415} {
		services = append(services, model.Service{
			PID: pid, Executable: "/usr/sbin/nginx", Endpoints: []string{"0.0.0.0:80/tcp"},
			Components: []string{"pkg:apk/alpine/nginx@1"},
		})
	}
	// A different daemon from the same binary on a different port stays its
	// own service.
	services = append(services, model.Service{
		PID: 600, Executable: "/usr/sbin/nginx", Endpoints: []string{"0.0.0.0:8443/tcp"},
	})

	got := collapseWorkers(services)
	if len(got) != 2 {
		t.Fatalf("got %d services, want 2: %+v", len(got), got)
	}
	if got[0].Processes != 3 {
		t.Errorf("processes = %d, want 3", got[0].Processes)
	}
	// The master, which is the lowest pid.
	if got[0].PID != 400 {
		t.Errorf("pid = %d, want the lowest (the master)", got[0].PID)
	}
	// A single-process service says nothing rather than "processes: 1".
	if got[1].Processes != 0 {
		t.Errorf("a lone service reported processes = %d", got[1].Processes)
	}
}

func TestCollapseWorkersLeavesDistinctServicesAlone(t *testing.T) {
	services := []model.Service{
		{PID: 1, Executable: "/usr/sbin/nginx", Endpoints: []string{"0.0.0.0:80/tcp"}},
		{PID: 2, Executable: "/usr/sbin/sshd", Endpoints: []string{"0.0.0.0:22/tcp"}},
	}
	if got := collapseWorkers(services); len(got) != 2 {
		t.Errorf("collapsed two different daemons into %d", len(got))
	}
}
