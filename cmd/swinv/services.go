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

	// Containers before exposure: a published host port's identity is the
	// software inside the container behind it, so that has to be resolved
	// first, and publishing it is then recorded back onto the container's own
	// service.
	if !cfg.noContainers {
		report.Containers = service.EnrichContainers("", snapshot.Containers, cfg.noServiceCommand)
	}
	report.Exposure = service.Expose(snapshot, services, report.Containers)

	// The packages found inside containers join the inventory. Without this
	// their PURLs exist only in containers[], which breaks CVE matching for
	// every consumer that reads components[] and nothing else -- most of them,
	// `grype sbom:` included -- and leaves the CycloneDX dependency edges
	// pointing at bom-refs no component has. Each carries the scope it was
	// found at, because only the packages owning a listening executable were
	// probed and these rows are not the container's inventory.
	if extra := service.ContainerComponents(report.Containers); len(extra) > 0 {
		report.Components = model.Normalize(append(report.Components, extra...))
		logf("services: %d package(s) from inside containers added to the inventory", len(extra))
	}

	// Named in the document, not only in the docs. An ingest pipeline drops
	// prose, and these are the only thing that distinguishes "nothing is
	// exposed" from "the exposure could not be observed".
	report.Scan.ExposureBlindSpots = service.DetectBlindSpots(cfg.root, report.Scan.RanAsRoot)
	// Containers whose software could not be named. On Windows this is every
	// one of them, because the filesystem is inside a virtual machine; the
	// image is still reported, and an image reference is not something a
	// vulnerability matcher can resolve.
	if unreadable := containersWithoutPackages(report.Containers); unreadable > 0 {
		report.Scan.ExposureBlindSpots = append(report.Scan.ExposureBlindSpots,
			service.BlindContainerFilesystem)
	}
	// Always false, always emitted. The constant is the whole difference
	// between "no firewall rules were found" and "firewall rules were never
	// read" for anyone building an exposure report on this.
	report.Scan.FirewallExamined = false

	logf("services: %s", summariseServices(services))
	logf("exposure: %s", summariseExposure(report.Exposure, report.Containers))
}

// containersWithoutPackages counts containers where no service could be tied
// to a package the container itself installed.
func containersWithoutPackages(containers []model.Container) int {
	var n int
	for _, c := range containers {
		named := false
		for _, s := range c.Services {
			if len(s.Components) > 0 {
				named = true
				break
			}
		}
		if !named {
			n++
		}
	}
	return n
}

// summariseExposure is the line an operator reads about the network edge. It
// leads with what is bound beyond loopback, because that is the number the
// question was asked about.
func summariseExposure(exposure []model.Exposure, containers []model.Container) string {
	var beyondLoopback, identified, osComponents int
	for _, e := range exposure {
		if e.BindScope == model.BindLoopback {
			continue
		}
		beyondLoopback++
		switch {
		case len(e.Components) > 0:
			identified++
		case e.OSComponent:
			osComponents++
		}
	}
	var containerServices int
	for _, c := range containers {
		containerServices += len(c.Services)
	}
	summary := fmt.Sprintf("%d of %d endpoint(s) bound beyond loopback, %d of those identified",
		beyondLoopback, len(exposure), identified)
	if osComponents > 0 {
		// Named separately so they are not read as unmanaged software, which
		// is what an operating-system binary would otherwise look like.
		summary += fmt.Sprintf(", %d served by the operating system", osComponents)
	}
	return summary + fmt.Sprintf("; %d container(s) with %d listening service(s)",
		len(containers), containerServices)
}

// summariseServices is the one line an operator reads about this section. It
// leads with the medium-confidence count because that is the finding a package
// inventory alone cannot produce: software serving traffic that nothing
// installed accounts for.
func summariseServices(services []model.Service) string {
	var high, medium, low, osComponents int
	for _, s := range services {
		switch {
		case s.Confidence == model.ConfidenceHigh:
			high++
		case s.OSComponent:
			// Counted apart from "nothing installed": an operating-system
			// binary is not software running outside package management, and
			// on Windows it is most of what listens.
			osComponents++
		case s.Confidence == model.ConfidenceMedium:
			medium++
		default:
			low++
		}
	}
	out := fmt.Sprintf("%d attributed to installed software, %d running software nothing installed",
		high, medium)
	if osComponents > 0 {
		out += fmt.Sprintf(", %d part of the operating system", osComponents)
	}
	return out + fmt.Sprintf(", %d unidentified", low)
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

// writeExposureCSV writes the exposure sidecar next to the component CSV.
//
// A separate file from the services one because the two have different units:
// a service is a process, an exposure row is a socket, and a consumer whose
// job is the network edge wants the second without having to explode the
// first.
func writeExposureCSV(cfg *config, report *model.Report, base string, logf func(string, ...any), stderr io.Writer) int {
	if report.Exposure == nil {
		return exitOK
	}
	return writeSidecar(cfg, report, base, "-exposure.csv", output.WriteExposureCSV, logf, stderr)
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
	return writeSidecar(cfg, report, base, "-services.csv", output.WriteServicesCSV, logf, stderr)
}

// writeSidecar writes one sidecar file and maintains its -latest symlink.
func writeSidecar(cfg *config, report *model.Report, base, suffix string,
	write func(io.Writer, *model.Report) error, logf func(string, ...any), stderr io.Writer) int {

	target := filepath.Join(cfg.out, base+suffix)
	if err := output.AtomicWriteFile(target, cfg.filePerm, func(w io.Writer) error {
		return write(w, report)
	}); err != nil {
		fmt.Fprintf(stderr, "swinv: writing %s: %v\n", target, err)
		return exitFatal
	}
	logf("wrote %s", target)

	if cfg.latestSymlink {
		link := filepath.Join(cfg.out, latestBase(report)+suffix)
		if link != target {
			if err := output.UpdateSymlink(link, filepath.Base(target)); err != nil {
				fmt.Fprintf(stderr, "swinv: warning: updating %s: %v\n", link, err)
			}
		}
	}
	return exitOK
}
