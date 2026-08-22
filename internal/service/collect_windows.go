//go:build windows

package service

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCP = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDP = iphlpapi.NewProc("GetExtendedUdpTable")
)

// The kernel process. It holds the ports served by kernel-mode drivers --
// SMB via srv2.sys, NetBIOS -- and no handle can be opened to it, so its
// executable is never readable and has to be named rather than resolved.
const (
	systemProcessPID  = 4
	systemProcessName = "System"
)

// Address families and table classes, from winsock2.h and iphlpapi.h.
const (
	afINET  = 2
	afINET6 = 23

	tcpTableOwnerPIDListener = 3 // TCP_TABLE_OWNER_PID_LISTENER
	udpTableOwnerPID         = 1 // UDP_TABLE_OWNER_PID
)

// collect reports what is listening on Windows.
//
// The mechanism is different from Linux and the honesty is the same. There is
// no /proc: iphlpapi hands back the socket tables with an owning pid already
// attached, so nothing has to be joined through file descriptors, and an
// unprivileged run sees the same sockets. What it cannot do without elevation
// is read another user's executable path, so the socket is still reported and
// the process behind it is not -- the same degradation, from a different
// cause.
func collect(ctx context.Context, _ string) (*Result, error) {
	var sockets []winSocket
	var warnings []string

	for _, t := range []struct {
		name  string
		fetch func() ([]byte, error)
		parse func([]byte) []winSocket
	}{
		{"tcp", func() ([]byte, error) { return extendedTable(procGetExtendedTCP, afINET, tcpTableOwnerPIDListener) }, parseTCPTable4},
		{"tcp6", func() ([]byte, error) { return extendedTable(procGetExtendedTCP, afINET6, tcpTableOwnerPIDListener) }, parseTCPTable6},
		{"udp", func() ([]byte, error) { return extendedTable(procGetExtendedUDP, afINET, udpTableOwnerPID) }, parseUDPTable4},
		{"udp6", func() ([]byte, error) { return extendedTable(procGetExtendedUDP, afINET6, udpTableOwnerPID) }, parseUDPTable6},
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := t.fetch()
		if err != nil {
			// A host with IPv6 disabled has no tcp6 table. Missing one table
			// is not a failed scan.
			warnings = append(warnings, fmt.Sprintf("could not read the %s socket table: %v", t.name, err))
			continue
		}
		sockets = append(sockets, t.parse(raw)...)
	}

	if len(sockets) == 0 {
		return &Result{Warnings: warnings}, nil
	}

	byPID := make(map[int]*Service)
	var order []int
	unreadable := 0
	for _, s := range sockets {
		svc, ok := byPID[s.PID]
		if !ok {
			exe, err := processImage(s.PID)
			if err != nil {
				// The kernel's own process cannot be opened at all, and it is
				// what serves SMB and NetBIOS. Reporting 445 and 139 as
				// software nobody could identify, on every Windows host, is
				// both wrong and the noisiest possible way to be wrong.
				if s.PID == systemProcessPID {
					exe = systemProcessName
				} else {
					unreadable++
				}
			}
			svc = &Service{
				Process:     Process{PID: s.PID, Exe: exe},
				HostNetwork: true,
			}
			byPID[s.PID] = svc
			order = append(order, s.PID)
		}
		svc.Endpoints = append(svc.Endpoints, Endpoint{
			Protocol: s.Protocol, Address: s.Address, Port: s.Port,
		})
	}
	if unreadable > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"the executable behind %d listening process(es) could not be read; "+
				"reading another account's process image needs an elevated prompt",
			unreadable))
	}

	services := make([]Service, 0, len(order))
	for _, pid := range order {
		s := byPID[pid]
		sort.Slice(s.Endpoints, func(i, j int) bool {
			if s.Endpoints[i].Port != s.Endpoints[j].Port {
				return s.Endpoints[i].Port < s.Endpoints[j].Port
			}
			return s.Endpoints[i].Protocol < s.Endpoints[j].Protocol
		})
		services = append(services, *s)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Process.PID < services[j].Process.PID })

	return withDockerPublishes(&Result{Services: services, Warnings: warnings}), nil
}

// extendedTable calls one of the GetExtended*Table pair, growing the buffer
// until it fits.
//
// The size is negotiated: the first call reports how much is needed, and the
// table can grow between the two, so a short read is retried rather than
// treated as an error.
func extendedTable(proc *windows.LazyProc, family, class uintptr) ([]byte, error) {
	const maxAttempts = 5
	var size uint32

	for attempt := 0; attempt < maxAttempts; attempt++ {
		var buf []byte
		var ptr unsafe.Pointer
		if size > 0 {
			buf = make([]byte, size)
			ptr = unsafe.Pointer(&buf[0])
		}
		ret, _, _ := proc.Call(
			uintptr(ptr),
			uintptr(unsafe.Pointer(&size)),
			0, // bOrder: FALSE, sorting is done here
			family,
			class,
			0,
		)
		switch windows.Errno(ret) {
		case windows.ERROR_SUCCESS:
			if buf == nil {
				return nil, nil
			}
			if int(size) < len(buf) {
				buf = buf[:size]
			}
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			continue
		default:
			return nil, windows.Errno(ret)
		}
	}
	return nil, fmt.Errorf("the socket table kept growing across %d attempts", maxAttempts)
}

// processImage resolves a pid to its executable path.
//
// PROCESS_QUERY_LIMITED_INFORMATION rather than the full query right: it is
// the least that answers this question, and it works against processes an
// elevated scan would otherwise be refused for.
func processImage(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("no owning process")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(h) }()

	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return filepath.Clean(windows.UTF16ToString(buf[:n])), nil
}

// Supported reports whether this platform can enumerate listening sockets.
func Supported() bool { return true }

// dockerPublishes is filled from the engine when one is reachable; see
// container_windows.go.
func withDockerPublishes(r *Result) *Result {
	r.Publishes = DockerPublishes()
	r.HostNamespace = "windows-host"
	return r
}
