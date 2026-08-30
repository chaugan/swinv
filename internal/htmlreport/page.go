package htmlreport

import (
	"fmt"
	"html"
	"strings"

	"github.com/chaugan/swinv/internal/model"
)

// buildPage assembles the full HTML document. The body markup mirrors the
// report's design: a masthead, a figure strip whose every tile names the flag
// that produced its number, ruled collapsible sections, and - on each block -
// a provenance tag naming its governing flag. The heavy data and the drawn
// charts live in the embedded JS.
func buildPage(r *model.Report, data reportData, blob string) string {
	p := r.Scan.Profile
	if p == nil {
		p = &model.ScanProfile{ELFScope: "off", ConfigScope: "off", Root: "/"}
	}
	flCfg := "--config-scope " + orDash(p.ConfigScope)
	flElf := "--elf-scope " + orDash(p.ELFScope)
	flSvc := "--services"
	if !p.Services {
		flSvc = "--no-services"
	}
	flCtr := "--containers"
	if !p.Containers {
		flCtr = "--no-containers"
	}

	c := data.Meta.Counts
	esc := html.EscapeString

	figs := fig(comma(c["component"]), "installed components", "catalogers · always on", true) +
		fig(comma(c["config"]), "config surface", flCfg, p.ConfigScope != "off") +
		fig(comma(c["exposure"]), "listening ports", flSvc, p.Services) +
		fig(comma(c["link"]), "library links", flElf, p.ELFScope != "off") +
		fig(comma(c["container"]), "containers", flCtr, p.Containers)

	cmdNote := "Reconstructed from the scan profile recorded in the report — the flags whose data this page shows. Defaults are omitted."
	if len(p.Args) > 0 {
		cmdNote = "The exact invocation recorded with this scan, shown with the program name normalised to <span class=\"mono\">swinv</span>."
	}
	s1 := `<div class="block" style="margin-bottom:26px"><h3>The command that produced this data</h3>` +
		`<div class="cmd"><span class="dollar">$</span> <code>` + esc(cmdLine(p, r)) + `</code></div>` +
		`<div class="cmdnote">` + cmdNote + `</div>` +
		`<div class="chips" style="margin-top:16px">` + flagChips(p) + `</div>` +
		`<div style="margin-top:11px;font-size:12px;color:var(--muted);font-family:-apple-system,sans-serif">Root scanned <span class="mono">` + esc(orDash(p.Root)) + `</span></div></div>` +
		`<div class="block">` + bh("Cataloger health", "every source probed", true) +
		`<table><thead><tr><th>Source</th><th>Status</th><th>Components</th><th>Reason, if not OK</th></tr></thead><tbody>` +
		sourcesRows(r.Scan.Sources) + `</tbody></table></div>`

	s2 := `<div class="grid2" style="margin-bottom:26px">` +
		`<div class="risk"><h3 style="border:0;color:var(--red);padding:0;margin-bottom:2px">Unowned code in the privilege surface</h3>` +
		`<div class="lead">Libraries and persistence executables that resolve to no package — code a package manager cannot patch or correlate to a CVE.</div>` +
		`<div class="rn">` +
		riskNum(comma(data.Insights.UnownedLinkCount), "unowned library links") +
		riskNum(fmt.Sprint(len(data.Insights.UnownedExecConfigs)), "unowned persistence executables") +
		riskNum(fmt.Sprint(data.Insights.BeyondLoopback), "ports bound beyond loopback") +
		`</div></div>` +
		`<div class="block">` + bh("Config surface by ATT&amp;CK technique", flCfg, false) + `<div id="ch-attack"></div></div></div>` +
		`<div class="block" style="margin-bottom:26px">` + bh("Listening ports", flSvc, false) + `<div id="tb-exp"></div></div>` +
		`<div class="block" style="margin-bottom:26px">` + bh("Persistence &amp; privilege records", flCfg, false) + `<div id="tb-cfg"></div></div>` +
		interfaceBlock(p, data)

	s3 := `<div class="grid2" style="margin-bottom:26px">` +
		`<div class="block">` + bh("By component type", "catalogers", true) + `<div id="ch-type"></div></div>` +
		`<div class="block">` + bh("By filesystem root", flCtr, false) + `<div id="ch-root"></div>` +
		`<h3 style="margin-top:22px">By cataloger source<span class="prov gen">catalogers</span></h3><div id="ch-src"></div></div></div>` +
		`<div class="block"><div id="tb-comp"></div></div>`

	s4 := `<div class="block" style="margin-bottom:26px">` + bh("Ownership of loaded libraries", flElf, false) + `<div id="ch-own"></div>` +
		`<div class="lead" style="margin-top:8px">Unowned libraries are the case worth reading: loaded at runtime, owned by no package. This scan found <b>` + comma(data.Insights.UnownedLinkCount) + `</b>.</div></div>` +
		`<div class="block">` + bh("Unowned library links", flElf, false) + `<div id="tb-unl"></div></div>`

	s5 := `<div class="block"><div id="tb-ct"></div></div>`

	body := mast(data) +
		`<div class="figs">` + figs + `</div>` +
		`<div class="note">` + warnSVG + `<div><b>Coverage, not a verdict.</b> This report reflects exactly what the scan was asked to collect — see the scan profile. A source that was skipped or out of scope reads <b>—</b>, never zero. A narrower scan is not remediation; absence in an unscanned source is unknown, not clean.</div></div>` +
		sec("Coverage &amp; scan profile", "what produced this data, and which catalogers ran", s1, "the scan manifest") +
		sec("Exposure &amp; privilege surface", "what an attacker can reach, and what runs privileged", s2, flSvc+"  ·  "+flCfg) +
		sec("Installed software", fmt.Sprintf("%s components — click a bar to filter the table", comma(c["component"])), s3, "catalogers · always on") +
		sec("Shared libraries", fmt.Sprintf("%s link records — what every binary actually loads", comma(c["link"])), s4, flElf) +
		sec("Containers", fmt.Sprintf("%s containers, each its own operating system", comma(c["container"])), s5, flCtr) +
		`<div class="foot">Generated by swinv — self-contained and offline. No data left this machine to build this page.</div>`

	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + esc(data.Meta.Host) + ` — inventory</title><style>` + css + `</style></head><body><div class="wrap">` +
		body +
		`</div><script type="application/json" id="swinv-data">` + blob + `</script><script>` + js + renderCalls + `</script></body></html>`
}

// interfaceBlock renders the network-interfaces block, stating the flag that
// governs it either way: a table of every interface when --all-interfaces was
// on, and an explicit "not collected" where an empty table would read as a
// machine with no network. Absence is unknown, not clean - the same rule the
// coverage note at the top of the page states.
func interfaceBlock(p *model.ScanProfile, data reportData) string {
	if p == nil || !p.AllInterfaces {
		return `<div class="block" style="margin-bottom:26px">` +
			bh("Network interfaces", "--all-interfaces off", false) +
			`<div class="lead">Not collected: this scan ran without <span class="mono">--all-interfaces</span>. Only the usable identity appears in the report — the non-loopback addresses of interfaces that are up, in the host block — and every other interface and address, loopback and link-local included, is unknown.</div>` +
			`</div>`
	}
	return `<div class="block" style="margin-bottom:26px">` +
		bh("Network interfaces", "--all-interfaces", false) +
		`<div class="lead">Every interface with every address — loopback, link-local and down included, addresses in CIDR form. The usable identity in the host block is the subset that leaves the machine. The type is a best-effort classification: <span class="mono">ethernet</span> means “not one of the named kinds”, not “a physical port”.</div>` +
		`<div id="tb-iface"></div></div>`
}

func mast(d reportData) string {
	e := html.EscapeString
	return `<div class="mast"><div><h1>Software inventory</h1>` +
		`<div class="host">` + e(d.Meta.Host) + `</div>` +
		`<div class="meta">` + e(d.Meta.OS) + ` · kernel ` + e(orDash(d.Meta.Kernel)) + `</div></div>` +
		`<div class="right">scanned <b>` + e(d.Meta.ScannedAt) + `</b><br>swinv <b>` + e(d.Meta.Swinv) + `</b><br>source <span class="mono">` + e(d.Meta.SourcePath) + `</span></div></div>`
}

func fig(n, label, src string, on bool) string {
	cls, ncls := "", ""
	if !on {
		cls, ncls = " off", " off"
	}
	return `<div class="fig` + cls + `"><div class="n` + ncls + `">` + html.EscapeString(n) + `</div>` +
		`<div class="l">` + html.EscapeString(label) + `</div><div class="src">` + html.EscapeString(src) + `</div></div>`
}

func riskNum(v, k string) string {
	return `<div><div class="v">` + html.EscapeString(v) + `</div><div class="k">` + html.EscapeString(k) + `</div></div>`
}

func bh(title, flag string, gen bool) string {
	cls := "prov"
	if gen {
		cls = "prov gen"
	}
	fb := ""
	if flag != "" {
		fb = `<span class="` + cls + `" title="the flag that produced this data">` + html.EscapeString(flag) + `</span>`
	}
	return `<h3>` + title + fb + `</h3>`
}

func sec(title, desc, body, flag string) string {
	fb := ""
	if flag != "" {
		fb = `<span class="prov">` + html.EscapeString(flag) + `</span>`
	}
	return `<section><div class="shead" onclick="toggle(this)"><h2>` + title + `</h2><span class="d">` + html.EscapeString(desc) + `</span>` + fb + `<span class="car">▼</span></div><div class="sbody">` + body + `</div></section>`
}

func flagChips(p *model.ScanProfile) string {
	b := func(lab, val string, on bool) string {
		if val != "" {
			return `<span class="c">` + lab + ` <b class="on">` + html.EscapeString(val) + `</b></span>`
		}
		cls := ""
		state := "on"
		if !on {
			cls, state = " off", "off"
		}
		return `<span class="c` + cls + `">` + lab + ` <b>` + state + `</b></span>`
	}
	out := b("full-scan", "", p.FullScan) +
		b("hash", "", p.Hash) +
		b("all-interfaces", "", p.AllInterfaces) +
		b("elf-scope", orDash(p.ELFScope), true) +
		b("config-scope", orDash(p.ConfigScope), true) +
		b("services", "", p.Services) +
		b("containers", "", p.Containers)
	out += `<span class="c">records <b class="on">` + html.EscapeString(strings.Join(p.NDJSONInclude, ", ")) + `</b></span>`
	return out
}

func sourcesRows(sources map[string]model.SourceStatus) string {
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sortStrings(names)
	var b strings.Builder
	for _, name := range names {
		s := sources[name]
		st := s.Status
		cls := map[string]string{"ok": "ok", "skipped": "skip", "failed": "bad", "error": "bad"}[st]
		cval := `<span class="dash">—</span>`
		if st == "ok" {
			cval = comma(s.Components)
		}
		b.WriteString(`<tr><td class="mono">` + html.EscapeString(name) + `</td><td><span class="st ` + cls + `">` + html.EscapeString(st) + `</span></td><td>` + cval + `</td><td style="color:var(--muted)">` + html.EscapeString(s.Reason) + `</td></tr>`)
	}
	return b.String()
}

const warnSVG = `<svg width="17" height="17" viewBox="0 0 17 17" fill="none" stroke="#9c2b25" stroke-width="1.5"><path d="M8.5 1.6 16 15H1L8.5 1.6Z" stroke-linejoin="round"/><path d="M8.5 6.4v4"/><circle cx="8.5" cy="12.5" r=".2" fill="#9c2b25" stroke="none"/></svg>`

// renderCalls wires the embedded JS to the DOM ids the markup declares.
const renderCalls = `
const dist=D.dist,R=D.rows;
hbar(document.getElementById('ch-type'),dist.comp_type.slice(0,12),function(l){window.__t.comp&&window.__t.comp.setColFilter(2,l);});
donut(document.getElementById('ch-root'),dist.comp_root);
hbar(document.getElementById('ch-src'),dist.comp_source.slice(0,10),function(l){window.__t.comp&&window.__t.comp.setColFilter(4,l);});
hbar(document.getElementById('ch-attack'),dist.cfg_attack.slice(0,10),function(l){window.__t.cfg&&window.__t.cfg.setColFilter(4,l);});
stacked(document.getElementById('ch-own'),dist.link_own);
window.__t.comp=mkTable(document.getElementById('tb-comp'),
 [{t:'Name'},{t:'Version'},{t:'Type',r:v=>'<span class="kind">'+esc(v)+'</span>'},{t:'Root'},{t:'Source'},{t:'PURL',r:v=>'<span class="mono">'+esc(v).slice(0,58)+'</span>'}],
 R.components,{ph:'Search '+D.meta.counts.component.toLocaleString()+' components'});
window.__t.cfg=mkTable(document.getElementById('tb-cfg'),
 [{t:'Kind',r:v=>'<span class="kind">'+esc(v)+'</span>'},{t:'Name'},{t:'Path',r:v=>'<span class="mono">'+esc(v)+'</span>'},{t:'User'},{t:'ATT&CK',r:v=>v?'<span class="att">'+esc(v)+'</span>':''},{t:'Executable',r:v=>'<span class="mono">'+esc(v)+'</span>'},{t:'Owner',r:v=>v?'<span class="mono">'+esc(v).slice(0,38)+'</span>':'<span class="unowned">unowned</span>'},{t:'WW',r:v=>v?'<span class="ww">world-writable</span>':''},{t:'Evidence',r:v=>'<span class="ev">'+esc(v)+'</span>'}],
 R.config,{per:30});
window.__t.exp=mkTable(document.getElementById('tb-exp'),
 [{t:'Address'},{t:'Port'},{t:'Proto'},{t:'Bind',r:v=>v==='loopback'?'<span class="bind">'+esc(v)+'</span>':'<span class="bind ext">'+esc(v)+'</span>'},{t:'Executable',r:v=>'<span class="mono">'+esc(v)+'</span>'},{t:'Owner',r:v=>v?'<span class="mono">'+esc(v).slice(0,38)+'</span>':'<span class="unowned">unattributed</span>'},{t:'Conf.'},{t:'Unit'},{t:'User'}],
 R.exposure,{per:30});
window.__t.unl=mkTable(document.getElementById('tb-unl'),
 [{t:'Executable',r:v=>'<span class="mono">'+esc(v)+'</span>'},{t:'Library (soname)'},{t:'Resolved path',r:v=>'<span class="mono">'+esc(v)+'</span>'}],
 R.unowned_links,{per:30});
var ifaceHost=document.getElementById('tb-iface');
if(ifaceHost){window.__t.iface=mkTable(ifaceHost,
 [{t:'Name',r:v=>'<span class="mono">'+esc(v)+'</span>'},{t:'Type',r:v=>v?'<span class="kind">'+esc(v)+'</span>':''},{t:'State',r:v=>v==='up'?'<span class="st ok">up</span>':'<span class="st skip">down</span>'},{t:'MTU'},{t:'MAC',r:v=>v?'<span class="mono">'+esc(v)+'</span>':''},{t:'Addresses',r:v=>'<span class="mono">'+esc(v)+'</span>'}],
 R.interfaces,{per:30});}
window.__t.ct=mkTable(document.getElementById('tb-ct'),
 [{t:'ID',r:v=>'<span class="mono">'+esc(v)+'</span>'},{t:'Name'},{t:'Operating system'},{t:'State'},{t:'Image'}],
 R.containers,{per:30});
`

// cmdLine reconstructs the swinv invocation that would produce this report's
// data, from the scan profile the report recorded. Only non-default flags are
// shown, so the line reads as the operator would have typed it. It is a
// faithful reconstruction of scope, not a literal capture of argv: flags that
// leave no trace in the profile (output paths, --transmit, --quiet) cannot be
// recovered and are not guessed.
func cmdLine(p *model.ScanProfile, r *model.Report) string {
	if p == nil {
		return "swinv"
	}
	// When the scan recorded its invocation, show it verbatim -- it is the
	// exact command, including flags the scope fields cannot recover
	// (--offline, --heartbeat) and the output plumbing (--out, --format).
	if len(p.Args) > 0 {
		parts := make([]string, 0, len(p.Args)+1)
		parts = append(parts, "swinv")
		for _, arg := range p.Args {
			parts = append(parts, shellQuote(arg))
		}
		return strings.Join(parts, " ")
	}
	// Older reports (and files rebuilt with --report-from that predate the
	// recorded invocation) carry no args; reconstruct scope from the profile.
	var a []string
	a = append(a, "swinv")
	if p.Root != "" && p.Root != "/" {
		a = append(a, "--root "+shellQuote(p.Root))
	}
	if p.FullScan {
		a = append(a, "--full-scan")
	}
	if p.Hash {
		a = append(a, "--hash")
	}
	if p.AllInterfaces {
		a = append(a, "--all-interfaces")
	}
	if p.ELFScope != "" && p.ELFScope != "listening" {
		a = append(a, "--elf-scope "+p.ELFScope)
	}
	if p.ConfigScope != "" && p.ConfigScope != "standard" {
		a = append(a, "--config-scope "+p.ConfigScope)
	}
	if !p.Services {
		a = append(a, "--no-services")
	}
	if !p.Containers {
		a = append(a, "--no-containers")
	}
	if inc := ndjsonIncludeArg(p.NDJSONInclude); inc != "" {
		a = append(a, "--ndjson-include "+inc)
	}
	return strings.Join(a, " ")
}

// ndjsonIncludeArg renders the extra NDJSON record types as the flag value,
// dropping the always-present component records.
func ndjsonIncludeArg(inc []string) string {
	var extra []string
	for _, s := range inc {
		if s == "" || s == "component" {
			continue
		}
		extra = append(extra, s)
	}
	if len(extra) == 0 {
		return ""
	}
	return strings.Join(extra, ",")
}

// shellQuote single-quotes a value only when it contains something a shell
// would split or interpret, so a plain path stays readable.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		safe := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '/' || r == '.' || r == '_' || r == '-' || r == ':' || r == '\\'
		if !safe {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// comma formats an int with thousands separators.
func comma(n int) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, ch := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, ch)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
