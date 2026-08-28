//go:build windows

package hostfacts

import (
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/chaugan/swinv/internal/model"
)

// Registry locations for host identity. All are readable without elevation.
const (
	keyCurrentVersion = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	keyCryptography   = `SOFTWARE\Microsoft\Cryptography`
	keyBIOS           = `HARDWARE\DESCRIPTION\System\BIOS`
)

// platformFacts fills in the host identity that Linux reads from /etc and
// /proc and Windows keeps in the registry.
//
// Without it a Windows report carries a hostname and an architecture and
// nothing else: no os_id to group a fleet by, no machine_id to join on across
// runs after a rename. The components were right and the row identifying the
// machine they came from was blank.
//
// Only for the live system. A --root pointing at a mounted Linux image is a
// legitimate thing to do from Windows, and there the os-release the caller
// already read is the correct answer, not this machine's registry.
func platformFacts(h *model.Host, isSystemRoot bool) {
	if !isSystemRoot {
		return
	}

	cv, err := registry.OpenKey(registry.LOCAL_MACHINE, keyCurrentVersion, registry.QUERY_VALUE)
	if err == nil {
		defer cv.Close()

		build := regString(cv, "CurrentBuild")
		if build == "" {
			build = regString(cv, "CurrentBuildNumber")
		}

		// "windows" rather than an edition or a marketing name: os_id is a
		// grouping key, and its Linux counterpart is likewise the family
		// ("debian", "fedora") with the detail in os_version_id and
		// os_pretty_name.
		h.OSID = "windows"
		h.OSVersionID = windowsVersionID(
			regString(cv, "ProductName"), build, regString(cv, "InstallationType"))
		h.OSPrettyName = windowsPrettyName(regString(cv, "ProductName"), regString(cv, "DisplayVersion"), build)
		h.KernelRelease = windowsKernelRelease(
			regUint(cv, "CurrentMajorVersionNumber"),
			regUint(cv, "CurrentMinorVersionNumber"),
			build,
			regUint(cv, "UBR"),
		)

		// The patch-level join (issue #14): MSRC's CVRF keys remediations on
		// the OS build, and these four values are the whole join key. The
		// build string matches KernelRelease today; it gets its own field
		// because it is a statement of host identity, not of the kernel.
		h.OSBuild = h.KernelRelease
		h.OSDisplayVersion = regString(cv, "DisplayVersion")
		if h.OSDisplayVersion == "" {
			// Windows 10 before 20H2 spelled it ReleaseId ("1909").
			h.OSDisplayVersion = regString(cv, "ReleaseId")
		}
		h.OSEdition = regString(cv, "EditionID")
		h.OSInstallationType = regString(cv, "InstallationType")
	}

	// MachineGuid is written once when Windows is installed and survives
	// renames and address changes, which is what makes it the counterpart of
	// /etc/machine-id rather than anything hardware-derived.
	if crypto, err := registry.OpenKey(registry.LOCAL_MACHINE, keyCryptography, registry.QUERY_VALUE); err == nil {
		h.MachineID = normalizeMachineGUID(regString(crypto, "MachineGuid"))
		crypto.Close()
	}

	// The SMBIOS values Linux reads from /sys/class/dmi. Unlike Linux these
	// need no privilege, so an unelevated Windows run reports more hardware
	// identity than an unelevated Linux one.
	if bios, err := registry.OpenKey(registry.LOCAL_MACHINE, keyBIOS, registry.QUERY_VALUE); err == nil {
		h.SystemVendor = cleanDMI(regString(bios, "SystemManufacturer"))
		h.ProductName = cleanDMI(regString(bios, "SystemProductName"))
		bios.Close()
	}

	h.Virtualization = detectWindowsVirtualization(h.SystemVendor, h.ProductName)
}

// detectWindowsVirtualization identifies a hypervisor from the SMBIOS strings
// it advertises, the same signal Linux uses from DMI.
//
// Absence of a match means "not detected", not "bare metal": a hypervisor can
// be configured to present the host's real SMBIOS data precisely so guests
// cannot tell.
func detectWindowsVirtualization(vendor, product string) string {
	probe := strings.ToLower(vendor + " " + product)

	for _, c := range []struct{ needle, name string }{
		{"vmware", "vmware"},
		{"virtualbox", "oracle"},
		{"innotek", "oracle"},
		{"qemu", "qemu"},
		{"kvm", "kvm"},
		{"xen", "xen"},
		{"parallels", "parallels"},
		{"bochs", "bochs"},
		{"amazon ec2", "amazon"},
		{"google compute engine", "gce"},
		{"virtual machine", "microsoft"}, // Hyper-V presents "Virtual Machine"
	} {
		if strings.Contains(probe, c.needle) {
			return c.name
		}
	}
	return ""
}

func regString(k registry.Key, name string) string {
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// regUint reads a DWORD as a string, since every caller here is assembling a
// version string rather than doing arithmetic.
func regUint(k registry.Key, name string) string {
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return ""
	}
	return strconv.FormatUint(v, 10)
}
