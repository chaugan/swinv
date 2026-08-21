package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/chaugan/swinv/internal/model"
	"github.com/chaugan/swinv/internal/output"
	"github.com/chaugan/swinv/internal/service"
)

// listenSnapshot records what is listening, before the scan.
//
// Before, not after, because the attribution needs an answer the scan can only
// give if it is asked in advance: which package installed each listening
// executable. A component's recorded locations are its evidence files -- a deb
// records /var/lib/dpkg/status, never /usr/sbin/sshd -- so the join has to come
// from the package databases' file lists, and those are far too large to keep
// in order to answer forty questions. Collecting the sockets first turns an
// index into a membership test.
//
// Failure here is not failure of the inventory. A machine whose /proc cannot be
// read still has an installed-software list worth writing, so problems become
// warnings on the report and the component list is untouched.
func listenSnapshot(ctx context.Context, cfg *config, meta *model.ScanMeta, logf func(string, ...any)) *service.Result {
	if cfg.noServices || !service.Supported() {
		return nil
	}
	// --root pointed somewhere other than this machine: an image, a chroot, a
	// mounted disk. The sockets open right now belong to the host, not to the
	// tree being inventoried, and attributing them to that tree's packages
	// would be a confident wrong answer about a machine that is not running.
	if !scanningLiveHost(cfg.root) {
		meta.AddWarning(fmt.Sprintf(
			"services were not collected: --root is %s, and listening sockets describe "+
				"the running machine rather than the tree being scanned", cfg.root))
		return nil
	}

	start := time.Now()
	result, err := service.Collect(ctx, "")
	if err != nil {
		meta.AddWarning("could not enumerate listening sockets: " + err.Error())
		return nil
	}
	for _, w := range result.Warnings {
		meta.AddWarning(w)
	}
	if cfg.verbose {
		logf("services: %d listening process(es) in %s",
			len(result.Services), time.Since(start).Round(time.Millisecond))
	}
	return result
}

// attributeServices joins the snapshot to the finished inventory and files the
// answer on the report.
func attributeServices(cfg *config, report *model.Report, snapshot *service.Result, fileOwners map[string][]string, logf func(string, ...any)) {
	if snapshot == nil {
		return
	}
	services := service.Attribute(snapshot.Services, service.Inventory{
		FileOwners: fileOwners,
		Components: report.Components,
	}, snapshot.Unattributed)

	if cfg.noServiceCommand {
		for i := range services {
			services[i].Command = ""
		}
	}
	report.Services = services
	logf("services: %s", summariseServices(services))
}

// summariseServices is the one line an operator reads about this section. It
// leads with the medium-confidence count because that is the finding a package
// inventory alone cannot produce: software serving traffic that nothing
// installed accounts for.
func summariseServices(services []model.Service) string {
	var high, medium, low int
	for _, s := range services {
		switch s.Confidence {
		case model.ConfidenceHigh:
			high++
		case model.ConfidenceMedium:
			medium++
		default:
			low++
		}
	}
	return fmt.Sprintf("%d attributed to installed software, %d running software nothing installed, %d unidentified",
		high, medium, low)
}

// scanningLiveHost reports whether --root addresses the machine swinv is
// running on. filepath.Clean is what makes this correct on Windows, where the
// default --root of "/" cleans to "\".
func scanningLiveHost(root string) bool {
	if root == "" {
		return true
	}
	return filepath.Clean(root) == filepath.Clean("/")
}

// writeServicesCSV writes the services sidecar next to the component CSV.
//
// Sidecar rather than a --format of its own: an operator asking for CSV wants
// the inventory as CSV, and making them name a second format to get the other
// half of the same run is a trap. It is written whenever services were
// collected at all -- report.Services non-nil, even when empty -- because "we
// looked and found nothing listening" is a real result, and a missing file
// would be indistinguishable from a run where nobody asked.
func writeServicesCSV(cfg *config, report *model.Report, base string, logf func(string, ...any), stderr io.Writer) int {
	if report.Services == nil {
		return exitOK
	}
	target := filepath.Join(cfg.out, base+"-services.csv")
	if err := output.AtomicWriteFile(target, cfg.filePerm, func(w io.Writer) error {
		return output.WriteServicesCSV(w, report)
	}); err != nil {
		fmt.Fprintf(stderr, "swinv: writing %s: %v\n", target, err)
		return exitFatal
	}
	logf("wrote %s", target)

	if cfg.latestSymlink {
		link := filepath.Join(cfg.out, latestBase(report)+"-services.csv")
		if link != target {
			if err := output.UpdateSymlink(link, filepath.Base(target)); err != nil {
				fmt.Fprintf(stderr, "swinv: warning: updating %s: %v\n", link, err)
			}
		}
	}
	return exitOK
}
