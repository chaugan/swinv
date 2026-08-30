package htmlreport

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The chart JS has no DOM to test against from Go, but its geometry is where
// the bugs live: a label that wanders past the viewBox is cut off by the SVG
// in every browser. This test drives the real report.js under node - the same
// file the page embeds - and asserts the layout contracts directly: labels are
// tilted 45 degrees, every rotated label box sits inside the computed viewBox
// (nothing clipped at the top or bottom of the panel), overlapping labels are
// pushed apart, a long label pointing off the bottom of the ring grows the
// canvas downward instead of being truncated, and a slice count beyond the
// on-chart label cap falls back to the legend.
func TestReportJSDonutLayout(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available; donut layout is untested on this machine")
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	js, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "assets", "report.js"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(js); err != nil {
		t.Fatalf("report.js not found at %s: %v", js, err)
	}

	harness := `
const fs=require('fs'),vm=require('vm');
const measure={font:'',measureText:t=>({width:t.length*6.2})};
const ctx={document:{
  getElementById:()=>({textContent:'{}'}),
  createElement:kind=>kind==='canvas'?{getContext:()=>measure}:{},
}};
ctx.window=ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2],'utf8'),ctx);

let failures=0;
function check(name,cond){if(!cond){failures++;console.log('FAIL '+name);}else{console.log('ok   '+name);}}
function insideView(l,v){return l.box[0]>=v[0]&&l.box[1]>=v[1]&&l.box[2]<=v[0]+v[2]&&l.box[3]<=v[1]+v[3];}
function overlap(p,q){return p.box[0]<q.box[2]&&q.box[0]<p.box[2]&&p.box[1]<q.box[3]&&q.box[1]<p.box[3];}

// The reference case: the three filesystem roots of a real report. The
// "nested root" slice is small and points down-left; its label must pull the
// canvas down with it rather than being cut.
const roots=[["host (/)",13782],["container",965],["nested root",549]];
const lay=ctx.donutLayout(roots,t=>t.length*6.2+8);
check("layout returned",!!lay);
check("every label inside the viewBox",lay.labels.every(l=>insideView(l,lay.view)));
check("ring inside the viewBox",
  lay.view[0]<=-64&&lay.view[1]<=-64&&
  lay.view[0]+lay.view[2]>=64&&lay.view[1]+lay.view[3]>=64);

// The DOM path: labels tilted 45 degrees, leader lines, a sized viewBox.
const host={innerHTML:''};
ctx.donut(host,roots);
check("svg labels tilted 45 degrees",host.innerHTML.includes('rotate(-45)'));
check("svg carries a viewBox",host.innerHTML.includes('viewBox'));
check("leader lines drawn",host.innerHTML.includes('<line'));

// Long labels, worst case: two hanging off the bottom of the ring. The
// canvas must grow downward past the ring's own extent.
const long=[["a-very-long-filesystem-root-name-indeed",500],["b",500],["c",1],["d-down-here-with-a-long-name-too",400]];
const lay2=ctx.donutLayout(long,t=>t.length*6.2+8);
check("long labels inside the viewBox",lay2.labels.every(l=>insideView(l,lay2.view)));
check("canvas grew for the bottom labels",lay2.view[1]+lay2.view[3]>64+4);

let collisions=0;
for(let i=0;i<lay2.labels.length;i++)for(let j=i+1;j<lay2.labels.length;j++)
  if(overlap(lay2.labels[i],lay2.labels[j]))collisions++;
check("labels do not overlap",collisions===0);

// Labels belong next to their slices: the push-apart pass may only nudge a
// label when its box truly intersects another's, never shove a far-away label
// down the canvas. For the reference case every anchor stays within 100px of
// centre and the whole canvas stays compact (the regression this guards - a
// vertical-only push-apart once dragged a bottom-right label to y=152 on a
// radius-62 ring, nearly doubling the panel height).
check("reference labels stay near the ring",
  lay.labels.every(l=>Math.hypot(l.x,l.y)<=100));
check("reference canvas stays compact",lay.view[3]<=200);

// Too many slices: the legend fallback, not a collision of tilted labels.
const many=[];for(let i=0;i<12;i++)many.push(["root"+i,10]);
const host2={innerHTML:''};
ctx.donut(host2,many);
check("legend fallback beyond the label cap",host2.innerHTML.includes('class="legend"'));

if(failures){console.log(failures+" failure(s)");process.exit(1);}
console.log("OK");
`

	dir := t.TempDir()
	script := filepath.Join(dir, "donut_test.js")
	if err := os.WriteFile(script, []byte(harness), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, script, js).CombinedOutput()
	if err != nil {
		t.Fatalf("node harness failed:\n%s", out)
	}
	t.Logf("%s", out)
	if !strings.Contains(string(out), "\nOK") {
		t.Fatalf("harness did not report OK:\n%s", out)
	}
}
