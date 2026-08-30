// Package hostfacts gathers the identity of the machine being inventoried:
// hostname, machine-id, OS release, kernel, DMI board data, virtualization
// hints, and network addresses.
//
// Everything here is best-effort and read straight from kernel and userspace
// interfaces using the standard library only. The package deliberately does
// not shell out to hostnamectl, dmidecode, ip, or uname so that the resulting
// binary stays free of runtime dependencies.
//
// The contract for the whole package is: a missing, empty, or unreadable
// source yields an empty field. Collect never returns an error, never logs,
// and never panics. Unreadable root-only DMI values (the common case when
// swinv runs as an unprivileged user) are silently left empty - they are not
// worth a warning because they are expected.
package hostfacts

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/chaugan/swinv/internal/model"
)

const (
	// fqdnTimeout bounds the DNS work done for Host.FQDN. Name resolution on a
	// misconfigured host can block for a long time and an inventory run must
	// never hang on a cosmetic field.
	fqdnTimeout = 2 * time.Second

	// maxFileSize caps every read this package performs. All of the sources are
	// tiny (a UUID, a kernel version, a few DMI strings); the cap exists so a
	// hostile or corrupt fixture tree cannot make Collect allocate without
	// bound.
	maxFileSize = 1 << 20
)

// Paths relative to the filesystem root, in slash form. They are joined onto
// fsRoot so that tests can point Collect at a fixture tree.
const (
	pathHostname       = "etc/hostname"
	pathMachineID      = "etc/machine-id"
	pathDBusMachineID  = "var/lib/dbus/machine-id"
	pathBootID         = "proc/sys/kernel/random/boot_id"
	pathKernelRelease  = "proc/sys/kernel/osrelease"
	pathEtcOSRelease   = "etc/os-release"
	pathLibOSRelease   = "usr/lib/os-release"
	pathHypervisorType = "sys/hypervisor/type"
	pathDockerEnv      = ".dockerenv"
	pathContainerEnv   = "run/.containerenv"
	pathInitCgroup     = "proc/1/cgroup"

	pathDMISysVendor     = "sys/class/dmi/id/sys_vendor"
	pathDMIProductName   = "sys/class/dmi/id/product_name"
	pathDMIProductSerial = "sys/class/dmi/id/product_serial"
	pathDMIProductUUID   = "sys/class/dmi/id/product_uuid"
)

// Collect gathers machine identity from the filesystem rooted at fsRoot.
//
// It NEVER returns an error and never logs: an unreadable or missing source
// simply yields an empty field. fsRoot is the filesystem root to read facts
// from - "/" in normal operation, or a fixture tree in tests. An empty fsRoot
// is treated as "/".
//
// The two facts that cannot be obtained from a fixture tree - the DNS lookup
// behind Host.FQDN and the interface enumeration behind IPv4/IPv6/MACs - are
// skipped entirely when fsRoot is not "/", which keeps tests hermetic and
// offline.
//
// ctx bounds the DNS work only; cancelling it does not abort the (purely
// local, non-blocking) file reads. The returned Host has already been passed
// through (*model.Host).Normalize, so its slices are sorted and deduplicated.
// Option adjusts what Collect gathers.
type Option func(*options)

type options struct {
	skipFQDN      bool
	allInterfaces bool
}

// WithoutFQDN suppresses the reverse-DNS lookup used to fill Host.FQDN.
//
// That lookup is the only thing in swinv that talks to the network at all. It
// sends no inventory data - just the ordinary name resolution any program does
// - but it does reveal to the configured resolver that this host looked itself
// up. Callers that need "nothing leaves the machine" to be literally true pass
// this and lose only the FQDN field.
func WithoutFQDN() Option {
	return func(o *options) { o.skipFQDN = true }
}

// WithAllInterfaces collects the complete interface inventory into
// Host.Interfaces: every interface with every address, loopback, link-local
// and down included, each named, classified and carrying its own addresses.
//
// The default IPv4/IPv6/MACs stay what they always were - the usable identity,
// the subset another machine could reach - which is the right default: the
// full table adds little to an inventory join and a good deal to what a shared
// report discloses (every internal subnet, every downed management interface,
// the loopback range). It is local enumeration, all net.Interfaces and
// /sys/class/net: no network traffic, and --root does not redirect it, since
// it describes the machine that is running, not a mounted tree.
func WithAllInterfaces() Option {
	return func(o *options) { o.allInterfaces = true }
}

func Collect(ctx context.Context, fsRoot string, opts ...Option) (h model.Host) {
	var cfg options
	for _, apply := range opts {
		apply(&cfg)
	}
	root, isSystemRoot := normalizeRoot(fsRoot)

	// Belt and braces: this package promises never to panic, and it is called
	// from a collector whose whole point is to still produce a file when parts
	// of the machine are unreadable. Whatever has been filled in so far is
	// returned as-is.
	defer func() {
		if recover() != nil {
			h.Normalize()
		}
	}()

	h.Hostname = hostname(root, isSystemRoot)
	h.MachineID = firstNonEmpty(
		readFile(root, pathMachineID),
		readFile(root, pathDBusMachineID),
	)
	h.BootID = readFile(root, pathBootID)
	h.KernelRelease = readFile(root, pathKernelRelease)
	h.Architecture = runtime.GOARCH

	osRelease := readOSRelease(root)
	h.OSID = osRelease["ID"]
	h.OSVersionID = osRelease["VERSION_ID"]
	h.OSPrettyName = osRelease["PRETTY_NAME"]

	// DMI. product_serial and product_uuid are root-only on Linux; a failure
	// here is expected for an unprivileged run and is passed over in silence.
	h.SystemVendor = cleanDMI(readFile(root, pathDMISysVendor))
	h.ProductName = cleanDMI(readFile(root, pathDMIProductName))
	h.ProductSerial = cleanDMI(readFile(root, pathDMIProductSerial))
	h.ProductUUID = cleanDMI(readFile(root, pathDMIProductUUID))

	h.Virtualization = detectVirtualization(root, h.ProductName, h.SystemVendor)

	// Where the operating system keeps this somewhere other than the
	// filesystem, fill it in. On Windows that is the registry; everywhere else
	// this does nothing.
	platformFacts(&h, isSystemRoot)

	if isSystemRoot {
		if !cfg.skipFQDN {
			h.FQDN = lookupFQDN(ctx, h.Hostname)
		}
		h.IPv4, h.IPv6, h.MACs = interfaceAddrs()
		if cfg.allInterfaces {
			h.Interfaces = allInterfaces()
		}
	}

	h.Normalize()
	return h
}

// ParseOSRelease parses os-release(5) key/value data from r and returns the
// keys it understood. It is exported so the parser can be unit-tested directly
// against awkward input; Collect uses it internally.
//
// The dialect accepted is the shell-compatible subset that os-release defines:
//
//   - blank lines and lines whose first non-blank character is '#' are ignored;
//   - a line with no '=' is malformed and is skipped rather than reported;
//   - a value wrapped in single quotes is taken literally;
//   - a value wrapped in double quotes has backslash escapes resolved: "\n" and
//     "\t" become a newline and a tab, and any other backslash simply escapes
//     the character that follows it (so `\"`, `\\` and `\$` yield `"`, `\` and
//     `$`);
//   - a value with an unbalanced quote is not a quoted value and is kept
//     verbatim. A closing double quote that is itself escaped does not close
//     the value, so `A="abc\"` is unbalanced rather than truncated;
//   - an unquoted value is taken with surrounding whitespace trimmed.
//
// CRLF line endings are tolerated. A later assignment to the same key wins,
// matching shell semantics. ParseOSRelease never returns nil and never fails:
// unreadable input yields an empty map.
func ParseOSRelease(r io.Reader) map[string]string {
	out := make(map[string]string)
	if r == nil {
		return out
	}

	sc := bufio.NewScanner(io.LimitReader(r, maxFileSize))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			// Malformed: no assignment. Skip it silently.
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if key == "" {
			continue
		}
		out[key] = unquote(strings.TrimSpace(line[eq+1:]))
	}
	// A scanner error (an over-long line, a read failure) means we simply stop
	// early and return what we already parsed.
	return out
}

// unquote resolves the shell quoting rules described on ParseOSRelease.
func unquote(v string) string {
	if len(v) < 2 {
		return v
	}
	q := v[0]
	if q != '"' && q != '\'' {
		return v
	}
	if v[len(v)-1] != q {
		// Unbalanced quote. Not a quoted value; hand back what was written.
		return v
	}
	body := v[1 : len(v)-1]
	if q == '\'' {
		// Single quotes are literal in shell; no escape processing at all.
		return body
	}
	if trailingBackslashes(body)%2 == 1 {
		// The closing quote is escaped, so it does not actually close the
		// value. Treat the whole thing as unbalanced.
		return v
	}

	var b strings.Builder
	b.Grow(len(body))
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(body) {
			// Trailing lone backslash: drop it.
			break
		}
		i++
		switch body[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		default:
			b.WriteByte(body[i])
		}
	}
	return b.String()
}

// trailingBackslashes counts the run of backslashes at the end of s. An odd
// count means the character that follows s was escaped.
func trailingBackslashes(s string) int {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n
}

// normalizeRoot canonicalises fsRoot and reports whether it addresses the real
// system root. An empty fsRoot means "/".
func normalizeRoot(fsRoot string) (root string, isSystemRoot bool) {
	if strings.TrimSpace(fsRoot) == "" {
		return "/", true
	}
	root = filepath.Clean(fsRoot)
	return root, root == systemRootPath
}

// systemRootPath is what "the machine I am running on" looks like once
// filepath.Clean has been applied, on this platform.
//
// Not the literal "/". filepath.Clean rewrites separators, so on Windows it
// turns "/" -- which is still the default value of --root -- into "\", and a
// comparison against "/" is therefore false there. That made isSystemRoot
// false on every Windows run, which silently skipped the registry lookups that
// fill in the host block, and produced reports carrying a hostname, an
// architecture and nothing else.
var systemRootPath = filepath.Clean("/")

// hostname resolves the machine's short hostname.
//
// On the real system root the kernel's value via os.Hostname is authoritative.
// Against a fixture tree that value would describe the machine running the
// test rather than the tree, so etc/hostname is consulted first and os.Hostname
// is only a fallback.
func hostname(root string, isSystemRoot bool) string {
	if isSystemRoot {
		if name, err := os.Hostname(); err == nil && name != "" {
			return name
		}
		return firstLine(readFile(root, pathHostname))
	}
	if name := firstLine(readFile(root, pathHostname)); name != "" {
		return name
	}
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

// readOSRelease parses /etc/os-release, falling back to /usr/lib/os-release
// when the former is missing or yields nothing usable. It never returns nil.
func readOSRelease(root string) map[string]string {
	for _, rel := range []string{pathEtcOSRelease, pathLibOSRelease} {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		kv := ParseOSRelease(f)
		_ = f.Close()
		if len(kv) > 0 {
			return kv
		}
	}
	return map[string]string{}
}

// virtHint pairs a lowercase needle looked for in DMI strings with the
// virtualization name to report. Order is significant: the first match wins,
// so more specific needles come first.
var virtHints = []struct{ needle, name string }{
	{"kvm", "kvm"},
	{"qemu", "qemu"},
	{"vmware", "vmware"},
	{"virtualbox", "virtualbox"},
	{"innotek", "virtualbox"},
	{"xen", "xen"},
	{"hvm domu", "xen"},
	{"hyper-v", "hyperv"},
	{"hyperv", "hyperv"},
	{"bochs", "bochs"},
	{"parallels", "parallels"},
	{"bhyve", "bhyve"},
	{"amazon ec2", "amazon"},
	{"google compute engine", "google"},
	{"alibaba cloud", "alibaba"},
	{"openstack", "openstack"},
	// Hyper-V presents the unhelpfully generic "Virtual Machine" as its
	// product name, so this must be tested after every specific needle above.
	{"virtual machine", "hyperv"},
	{"microsoft corporation", "hyperv"},
}

// cgroupHints maps a substring of /proc/1/cgroup to a container runtime. The
// first match in this order wins.
var cgroupHints = []struct{ needle, name string }{
	{"/docker", "docker"},
	{"docker-", "docker"},
	{"/lxc", "lxc"},
	{"lxc.payload", "lxc"},
	{"libpod", "podman"},
	{"kubepods", "kubernetes"},
	{"/containerd", "containerd"},
	{"garden", "garden"},
}

// detectVirtualization applies a best-effort heuristic over container markers,
// DMI identifiers, and the paravirtualized-guest interface at
// /sys/hypervisor/type.
//
// Containers are checked first: when swinv runs inside a container on a virtual
// machine, the container is the more informative - and innermost - answer.
// An empty result is a perfectly acceptable outcome and means "bare metal, or
// could not tell".
func detectVirtualization(root, productName, sysVendor string) string {
	if v := detectContainer(root); v != "" {
		return v
	}
	for _, hay := range []string{productName, sysVendor} {
		if v := matchVirtHint(hay); v != "" {
			return v
		}
	}
	// Xen and some other paravirtualized guests expose their type here and may
	// carry no useful DMI data at all.
	if t := strings.ToLower(firstLine(readFile(root, pathHypervisorType))); t != "" {
		if v := matchVirtHint(t); v != "" {
			return v
		}
		return t
	}
	return ""
}

// matchVirtHint returns the virtualization name for the first hint found in s,
// or "" when none matches.
func matchVirtHint(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	for _, h := range virtHints {
		if strings.Contains(s, h.needle) {
			return h.name
		}
	}
	return ""
}

// detectContainer looks for the well-known markers a container runtime leaves
// behind. It returns "" when the process does not appear to be containerized.
func detectContainer(root string) string {
	if exists(root, pathDockerEnv) {
		return "docker"
	}
	if exists(root, pathContainerEnv) {
		return "podman"
	}
	cgroup := strings.ToLower(readFile(root, pathInitCgroup))
	if cgroup == "" {
		return ""
	}
	for _, h := range cgroupHints {
		if strings.Contains(cgroup, h.needle) {
			return h.name
		}
	}
	return ""
}

// lookupFQDN makes a bounded, best-effort attempt to find the machine's fully
// qualified domain name. It first asks for the canonical name of the short
// hostname and then falls back to a reverse lookup of the addresses that
// hostname resolves to. Any failure - including a cancelled ctx or no DNS at
// all - yields "" and is never fatal.
func lookupFQDN(ctx context.Context, host string) string {
	if host == "" || host == "localhost" {
		return ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, fqdnTimeout)
	defer cancel()

	r := net.DefaultResolver
	if cname, err := r.LookupCNAME(ctx, host); err == nil {
		if fqdn := canonicalName(cname); fqdn != "" {
			return fqdn
		}
	}

	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		names, err := r.LookupAddr(ctx, a)
		if err != nil {
			continue
		}
		for _, n := range names {
			if fqdn := canonicalName(n); fqdn != "" {
				return fqdn
			}
		}
	}
	return ""
}

// canonicalName normalises a DNS name and rejects anything that is not
// actually qualified (i.e. carries no domain part).
func canonicalName(n string) string {
	n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
	if n == "" || !strings.Contains(n, ".") {
		return ""
	}
	return n
}

// interfaceAddrs enumerates the machine's usable network identity. Loopback
// interfaces, interfaces that are administratively down, and link-local
// addresses are all skipped: none of them identify the host to anyone else.
func interfaceAddrs() (ipv4, ipv6, macs []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if mac := iface.HardwareAddr.String(); mac != "" {
			macs = append(macs, mac)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() ||
				ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				ipv4 = append(ipv4, v4.String())
				continue
			}
			ipv6 = append(ipv6, ip.String())
		}
	}
	return ipv4, ipv6, macs
}

// allInterfaces enumerates every interface on the machine, with none of
// interfaceAddrs' filtering: loopback, down interfaces, link-local and
// point-to-point addresses all belong in a complete interface inventory.
//
// Addresses keep the CIDR form the API hands over ("192.168.1.10/24") rather
// than being trimmed to bare IPs: the prefix is half the information, and the
// always-on usable identity already exists for consumers who want bare hosts.
// Anything that fails per-interface - a vanished interface, an unreadable
// address list - is skipped rather than fatal, the same policy as the rest of
// this package.
func allInterfaces() []model.NetInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]model.NetInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		ni := model.NetInterface{
			Name: iface.Name,
			Type: classifyInterface(iface.Flags, iface.Name),
			MTU:  iface.MTU,
			MAC:  iface.HardwareAddr.String(),
		}
		if iface.Flags&net.FlagUp != 0 {
			ni.State = "up"
		} else {
			ni.State = "down"
		}
		addrs, err := iface.Addrs()
		if err == nil {
			for _, a := range addrs {
				if s := a.String(); s != "" {
					ni.IPs = append(ni.IPs, s)
				}
			}
		}
		out = append(out, ni)
	}
	return out
}

// classifyInterface names what kind of interface this is, from the flags the
// kernel reports on every platform plus whatever the OS can refine.
//
// The order matters: a flag can only speak to what it says, so the specific
// kinds are checked before the generic ones, and ethernet - the fallback for
// anything broadcast-capable - is last but for "other". A VM's NIC and a
// container's veth both land on ethernet; that is the kernel's honest answer,
// and the model documents the field as "not one of the named kinds" rather
// than "physical".
func classifyInterface(flags net.Flags, name string) string {
	switch {
	case flags&net.FlagLoopback != 0:
		return "loopback"
	case flags&net.FlagPointToPoint != 0:
		// Tunnels, PPP, WireGuard: two ends, no broadcast domain. Checked
		// before the OS refinement because a refinement of the underlying
		// device would otherwise mislabel the tunnel on top of it.
		return "point-to-point"
	}
	if refined := refineInterfaceType(name); refined != "" {
		return refined
	}
	if flags&net.FlagBroadcast != 0 {
		return "ethernet"
	}
	return "other"
}

// dmiPlaceholders are the strings firmware vendors ship when a DMI field was
// never populated. Reporting them is worse than reporting nothing, because
// they look like real data when the inventory is aggregated.
var dmiPlaceholders = map[string]struct{}{
	"":                                     {},
	"to be filled by o.e.m.":               {},
	"to be filled by o.e.m":                {},
	"system serial number":                 {},
	"system product name":                  {},
	"system manufacturer":                  {},
	"system version":                       {},
	"default string":                       {},
	"not specified":                        {},
	"not applicable":                       {},
	"none":                                 {},
	"n/a":                                  {},
	"na":                                   {},
	"unknown":                              {},
	"o.e.m.":                               {},
	"chassis manufacture":                  {},
	"filled by o.e.m.":                     {},
	"00000000-0000-0000-0000-000000000000": {},
}

// cleanDMI trims a DMI value and discards known firmware placeholders.
func cleanDMI(v string) string {
	v = strings.TrimSpace(firstLine(v))
	if _, placeholder := dmiPlaceholders[strings.ToLower(v)]; placeholder {
		return ""
	}
	return v
}

// readFile reads rel (a slash-separated path relative to root) and returns its
// contents with surrounding whitespace trimmed. Every failure mode - the file
// is missing, is a directory, or cannot be read because the caller is not root
// - yields "" with no error and no log line.
func readFile(root, rel string) string {
	// O_NONBLOCK matters: every source this package reads is a small regular
	// file, but if one of those paths is a FIFO - whether by accident or
	// because someone put it there - a plain Open would block until a writer
	// appeared and hang the whole inventory run on a cosmetic field.
	f, err := os.OpenFile(filepath.Join(root, filepath.FromSlash(rel)),
		os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	// Check the descriptor we actually opened rather than stat-ing the path
	// separately, so the answer cannot change underneath us.
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}

	b, err := io.ReadAll(io.LimitReader(f, maxFileSize))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// exists reports whether rel is present under root. Any stat error, including
// a permission failure on a parent directory, counts as absent.
func exists(root, rel string) bool {
	_, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

// firstLine returns s up to its first newline, trimmed. Several of the sources
// read here are single-line files that some tools write with trailing content.
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// firstNonEmpty returns the first argument that is not the empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
