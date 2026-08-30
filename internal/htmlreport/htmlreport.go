// Package htmlreport renders a scan into a single self-contained HTML page:
// distribution charts, drill-downs, collapsible sections, and - on every data
// segment - the flag that produced it. No external requests, no CDN; the CSS
// and JS are embedded, the charts are inline SVG drawn by vanilla JS, and the
// data rides in one <script type="application/json"> blob. It is the same
// offline promise as the rest of swinv: nothing leaves the machine to build
// the page.
package htmlreport

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

//go:embed assets/report.css
var css string

//go:embed assets/report.js
var js string

// WriteHTML renders r as a self-contained HTML report to w. It does not close w.
func WriteHTML(w io.Writer, r *model.Report) error {
	if r == nil {
		return fmt.Errorf("htmlreport: nil report")
	}
	data := aggregate(r)
	blob, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("htmlreport: encoding data: %w", err)
	}
	page := buildPage(r, data, string(blob))
	_, err = io.WriteString(w, page)
	return err
}

// --- data shapes the embedded JS consumes (json tags must match report.js) ---

type kv struct { // [label, count]
	K string
	N int
}

func (p kv) MarshalJSON() ([]byte, error) { return json.Marshal([]any{p.K, p.N}) }

type reportData struct {
	Meta        meta               `json:"meta"`
	ScanProfile *model.ScanProfile `json:"scan_profile"`
	Sources     map[string]srcStat `json:"sources"`
	Dist        dist               `json:"dist"`
	Rows        rows               `json:"rows"`
	Insights    insights           `json:"insights"`
}

type meta struct {
	Host       string         `json:"host"`
	OS         string         `json:"os"`
	Kernel     string         `json:"kernel"`
	ScannedAt  string         `json:"scanned_at"`
	Swinv      string         `json:"swinv"`
	SourcePath string         `json:"source_path"`
	Counts     map[string]int `json:"counts"`
}

type srcStat struct {
	Status     string `json:"status"`
	Components int    `json:"components,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type dist struct {
	CompType   []kv `json:"comp_type"`
	CompSource []kv `json:"comp_source"`
	CompRoot   []kv `json:"comp_root"`
	CfgKind    []kv `json:"cfg_kind"`
	CfgAttack  []kv `json:"cfg_attack"`
	LinkOwn    []kv `json:"link_own"`
}

type rows struct {
	Components   [][]any `json:"components"`
	Config       [][]any `json:"config"`
	Exposure     [][]any `json:"exposure"`
	Containers   [][]any `json:"containers"`
	UnownedLinks [][]any `json:"unowned_links"`
	Interfaces   [][]any `json:"interfaces"`
}

type insights struct {
	UnownedLinkCount   int     `json:"unowned_link_count"`
	UnownedExecConfigs [][]any `json:"unowned_exec_configs"`
	WorldWritable      [][]any `json:"world_writable"`
	BeyondLoopback     int     `json:"beyond_loopback"`
}

// counter keeps insertion-independent, count-desc-then-label-asc ordering.
type counter struct {
	m     map[string]int
	order []string
}

func newCounter() *counter { return &counter{m: map[string]int{}} }
func (c *counter) add(k string) {
	if _, ok := c.m[k]; !ok {
		c.order = append(c.order, k)
	}
	c.m[k]++
}
func (c *counter) top(n int) []kv {
	ks := append([]string(nil), c.order...)
	sort.SliceStable(ks, func(i, j int) bool {
		if c.m[ks[i]] != c.m[ks[j]] {
			return c.m[ks[i]] > c.m[ks[j]]
		}
		return ks[i] < ks[j]
	})
	if n > 0 && len(ks) > n {
		ks = ks[:n]
	}
	out := make([]kv, 0, len(ks))
	for _, k := range ks {
		out = append(out, kv{k, c.m[k]})
	}
	return out
}

func aggregate(r *model.Report) reportData {
	byType, bySource, byRoot := newCounter(), newCounter(), newCounter()
	compRows := make([][]any, 0, len(r.Components))
	for _, c := range r.Components {
		root := c.Root
		if root == "" {
			root = "/"
		}
		byType.add(orQ(c.Type))
		bySource.add(orQ(c.SourceKey))
		switch {
		case root == "/":
			byRoot.add("host (/)")
		case strings.HasPrefix(root, "container:"):
			byRoot.add("container")
		default:
			byRoot.add("nested root")
		}
		compRows = append(compRows, []any{c.Name, c.Version, orEmpty(c.Type), root, orEmpty(c.SourceKey), c.PURL})
	}

	// Links: flatten BinaryLinks, split ownership, collect unowned rows.
	var linkOwned, linkOS, linkUnowned int
	var unownedRows [][]any
	for _, b := range r.Links {
		for _, l := range b.Links {
			switch {
			case l.OSComponent:
				linkOS++
			case l.PURL != "":
				linkOwned++
			default:
				linkUnowned++
				if len(unownedRows) < 3000 {
					unownedRows = append(unownedRows, []any{b.Executable, l.Soname, l.Path})
				}
			}
		}
	}
	// Links attached to services are also link records; include their split so
	// the ownership total matches what the stream carried.
	for _, s := range r.Services {
		for _, l := range s.Links {
			switch {
			case l.OSComponent:
				linkOS++
			case l.PURL != "":
				linkOwned++
			default:
				linkUnowned++
				if len(unownedRows) < 3000 {
					unownedRows = append(unownedRows, []any{s.Executable, l.Soname, l.Path})
				}
			}
		}
	}

	cfgKind, cfgAttack := newCounter(), newCounter()
	cfgRows := make([][]any, 0, len(r.ConfigSurface))
	var unownedExec, worldW [][]any
	for _, c := range r.ConfigSurface {
		cfgKind.add(orQ(c.Kind))
		if c.Attack != "" {
			cfgAttack.add(c.Attack)
		} else {
			cfgAttack.add("(none)")
		}
		cfgRows = append(cfgRows, []any{c.Kind, c.Name, c.Path, c.User, c.Attack, c.Executable, c.PURL, c.WorldWritable, strings.Join(c.Evidence, "; ")})
		if c.Executable != "" && c.PURL == "" {
			unownedExec = append(unownedExec, []any{c.Kind, c.Executable, c.Attack})
		}
		if c.WorldWritable {
			worldW = append(worldW, []any{c.Kind, c.Path, c.User})
		}
	}

	expRows := make([][]any, 0, len(r.Exposure))
	beyond := 0
	for _, e := range r.Exposure {
		if string(e.BindScope) != "" && string(e.BindScope) != "loopback" {
			beyond++
		}
		purl := firstOr(e.Components, "")
		exe := e.Executable
		if e.Backend != nil && e.Backend.Executable != "" {
			exe = e.Backend.Executable
		}
		expRows = append(expRows, []any{e.Address, int(e.Port), e.Protocol, string(e.BindScope), exe, purl, string(e.Confidence), e.Unit, e.User})
	}

	ctRows := make([][]any, 0, len(r.Containers))
	for _, c := range r.Containers {
		img := ""
		if c.Image != nil {
			img = c.Image.Ref
		}
		os := strings.TrimSpace(c.OSID + " " + c.OSVersionID)
		ctRows = append(ctRows, []any{shortID(c.ID), c.Name, os, c.State, img})
	}

	// Interfaces ride only when the scan ran with --all-interfaces; an empty
	// list here is "not collected", and the page says so rather than showing
	// an empty table that reads as a machine with no network.
	ifaceRows := make([][]any, 0, len(r.Host.Interfaces))
	for _, ni := range r.Host.Interfaces {
		ifaceRows = append(ifaceRows, []any{
			ni.Name, ni.Type, ni.State, ni.MTU, ni.MAC, strings.Join(ni.IPs, ", "),
		})
	}

	m := meta{
		Host:       r.Host.Hostname,
		OS:         strings.TrimSpace(r.Host.OSID + " " + r.Host.OSVersionID),
		Kernel:     r.Host.KernelRelease,
		ScannedAt:  formatTime(r),
		Swinv:      r.Tool.Version,
		SourcePath: "",
		Counts: map[string]int{
			"component": len(r.Components),
			"config":    len(r.ConfigSurface),
			"exposure":  len(r.Exposure),
			"link":      linkOwned + linkOS + linkUnowned,
			"container": len(r.Containers),
		},
	}

	sources := map[string]srcStat{}
	for name, s := range r.Scan.Sources {
		sources[name] = srcStat{Status: s.Status, Components: s.Components, Reason: s.Reason}
	}

	return reportData{
		Meta:        m,
		ScanProfile: r.Scan.Profile,
		Sources:     sources,
		Dist: dist{
			CompType:   byType.top(14),
			CompSource: bySource.top(14),
			CompRoot:   byRoot.top(0),
			CfgKind:    cfgKind.top(12),
			CfgAttack:  cfgAttack.top(12),
			LinkOwn:    []kv{{"owned", linkOwned}, {"OS component", linkOS}, {"unowned", linkUnowned}},
		},
		Rows: rows{
			Components:   compRows,
			Config:       cfgRows,
			Exposure:     expRows,
			Containers:   ctRows,
			UnownedLinks: unownedRows,
			Interfaces:   ifaceRows,
		},
		Insights: insights{
			UnownedLinkCount:   linkUnowned,
			UnownedExecConfigs: unownedExec,
			WorldWritable:      worldW,
			BeyondLoopback:     beyond,
		},
	}
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
func orEmpty(s string) string { return s }
func firstOr(ss []string, d string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return d
}
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
func formatTime(r *model.Report) string {
	if !r.Scan.StartedAt.IsZero() {
		return r.Scan.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	return ""
}
