const D=JSON.parse(document.getElementById('swinv-data').textContent);
// monochrome ink-blue ramp; red reserved for the risk/unowned category
const RAMP=['#26425f','#345779','#436d92','#5f8aac','#84a8c4','#a9c3d7','#c9a15a','#7c8468','#9aa08a','#b7b6a4'];
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt=n=>n.toLocaleString();
function toggle(el){el.closest('section').classList.toggle('collapsed');}
function colorFor(label,i){return /unowned/i.test(label)?'#9c2b25':RAMP[i%RAMP.length];}

function hbar(host,data,onPick){
  // onPick, when given, is a function (label)=>{}. Click handlers are bound in
  // JS by row index below -- never by building an onclick="" attribute out of a
  // data-derived label, which would inject into the attribute on any label
  // containing a quote. The only data that reaches the DOM is escaped text.
  const max=Math.max(1,...data.map(d=>d[1])); const rh=26,w=host.clientWidth||500,lw=Math.min(190,Math.max(96,w*0.34));
  const bw=w-lw-62,h=data.length*rh+4;
  let s=`<svg width="100%" viewBox="0 0 ${w} ${h}" font-size="12">`;
  data.forEach((d,i)=>{const y=i*rh+2,bl=Math.max(2,d[1]/max*bw),col=colorFor(d[0],i);
    s+=`<g class="bar${onPick?' pick':''}" data-i="${i}">`+
       `<text x="${lw-9}" y="${y+16}" text-anchor="end" fill="#3c4148">${esc(d[0]).slice(0,28)}</text>`+
       `<rect class="b" x="${lw}" y="${y+4}" width="${bl}" height="${rh-11}" fill="${col}"/>`+
       `<text x="${lw+bl+7}" y="${y+16}" fill="#171a1e" font-weight="600">${fmt(d[1])}</text></g>`;});
  host.innerHTML=s+'</svg>';
  if(onPick)host.querySelectorAll('g.bar').forEach(g=>{g.style.cursor='pointer';g.addEventListener('click',()=>onPick(data[+g.dataset.i][0]));});
}
function donut(host,data){
  if(data.length>maxDonutLabels){donutLegend(host,data);return;}
  const lay=donutLayout(data,donutMeasurer());
  if(!lay){host.innerHTML='';return;}
  const v=lay.view;
  let s=`<svg viewBox="${v[0]} ${v[1]} ${v[2]} ${v[3]}" width="${v[2]}" height="${v[3]}" style="max-width:100%;height:auto" font-size="11" role="img" aria-label="donut chart">`;
  lay.paths.forEach(p=>{s+=`<path d="${p.d}" fill="${p.fill}"/>`;});
  lay.leaders.forEach(l=>{s+=`<line x1="${l[0]}" y1="${l[1]}" x2="${l[2]}" y2="${l[3]}" stroke="#b9b4a7" stroke-width="1"/>`;});
  lay.labels.forEach(l=>{s+=`<text transform="translate(${l.x} ${l.y}) rotate(-45)" text-anchor="${l.anchor}" fill="#3c4148">${esc(l.text)}<tspan font-weight="600" fill="#171a1e"> ${esc(l.count)}</tspan></text>`;});
  s+=`<text x="0" y="-1" text-anchor="middle" font-size="19" font-weight="600" fill="#171a1e">${fmt(lay.total)}</text>`;
  s+=`<text x="0" y="15" text-anchor="middle" font-size="10" fill="#71767e" letter-spacing=".08em">TOTAL</text></svg>`;
  host.innerHTML=s;
}

// donutMeasurer returns a text width measurer backed by canvas.measureText,
// with a character-count fallback for contexts without a canvas. The width
// drives the layout's collision and padding maths, so it must exist even
// where the full DOM does not.
function donutMeasurer(){
  try{const c=document.createElement('canvas').getContext('2d');
    if(c){c.font='11px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif';
      return t=>c.measureText(t).width+8;}}catch(e){}
  return t=>t.length*6.2+8;
}

// donutLayout computes the whole top-down donut in one pure function so it
// can be tested without a DOM. Everything is centred on (0,0); view is the
// tight viewBox.
//
// Labels sit outside their slice at the mid-angle, tilted 45 degrees (reading
// up-and-to-the-right), with a short leader line back to the slice and the
// slice's count riding along. The viewBox is the union of the ring and every
// label's rotated bounding box - grown, never clipped: a label hanging off
// the bottom of the ring grows the canvas downward rather than being cut at
// the panel edge. With more than maxDonutLabels slices the on-chart labels
// would collide, so the caller falls back to a legend instead.
const maxDonutLabels=8;
function donutLayout(data,measure){
  if(!data||!data.length)return null;
  const tot=data.reduce((a,b)=>a+b[1],0)||1,R=62,r=41;
  const TILT=-Math.PI/4,cs=Math.cos(TILT),sn=Math.sin(TILT);
  // Rotated bounding box of a text of width w, height h, anchored at (px,py)
  // with text-anchor start (dir 1) or end (dir -1), rotated by TILT.
  function rotBox(px,py,dir,w,h){
    const x0=dir>0?0:-w,x1=dir>0?w:0,y0=-h,y1=2; // -h..2 covers ascender and descender
    const pts=[[x0,y0],[x1,y0],[x1,y1],[x0,y1]].map(p=>[px+p[0]*cs-p[1]*sn,py+p[0]*sn+p[1]*cs]);
    const xs=pts.map(p=>p[0]),ys=pts.map(p=>p[1]);
    return [Math.min(...xs),Math.min(...ys),Math.max(...xs),Math.max(...ys)];
  }
  let a=-Math.PI/2;const paths=[],labels=[],leaders=[];
  data.forEach((d,i)=>{
    const f=d[1]/tot,a2=a+f*2*Math.PI,big=f>.5?1:0,
      x1=R*Math.cos(a),y1=R*Math.sin(a),x2=R*Math.cos(a2),y2=R*Math.sin(a2),
      xi2=r*Math.cos(a2),yi2=r*Math.sin(a2),xi1=r*Math.cos(a),yi1=r*Math.sin(a);
    paths.push({d:`M${x1} ${y1} A${R} ${R} 0 ${big} 1 ${x2} ${y2} L${xi2} ${yi2} A${r} ${r} 0 ${big} 0 ${xi1} ${yi1} Z`,fill:colorFor(d[0],i)});
    const mid=(a+a2)/2,dir=Math.cos(mid)>=0?1:-1,
      px=(R+10)*Math.cos(mid),py=(R+10)*Math.sin(mid),
      text=String(d[0]),full=text+' '+fmt(d[1]),w=measure(full),h=11;
    leaders.push([(R+2)*Math.cos(mid),(R+2)*Math.sin(mid),(R+8)*Math.cos(mid),(R+8)*Math.sin(mid)]);
    labels.push({text:text,count:fmt(d[1]),full:full,x:px,y:py,anchor:dir>0?'start':'end',box:rotBox(px,py,dir,w,h)});
    a=a2;
  });
  // Push apart only labels whose boxes truly overlap (both axes): vertical
  // separation is applied on contact, so a label on the left never shoves one
  // on the bottom down the canvas - they do not intersect, and moving either
  // would drag it away from its slice. Resolution repeats until no label
  // overlaps an earlier one - a single pass can push a label into a box it
  // had not been checked against - bounded so a pathological pile-up degrades
  // to a long canvas, never a hang.
  labels.slice().sort((p,q)=>p.box[1]-q.box[1]).forEach((l,idx,arr)=>{
    for(let pass=0;pass<20;pass++){
      let moved=false;
      for(let k=0;k<idx;k++){
        const p=arr[k];
        const dx=Math.min(p.box[2],l.box[2])-Math.max(p.box[0],l.box[0]);
        const dy=Math.min(p.box[3],l.box[3])-Math.max(p.box[1],l.box[1]);
        if(dx>0&&dy>0){
          l.y+=dy+2;
          l.box=rotBox(l.x,l.y,l.anchor==='start'?1:-1,measure(l.full),11);
          moved=true;
        }
      }
      if(!moved)break;
    }
  });
  let x0=-R-2,y0=-R-2,x1=R+2,y1=R+2;
  labels.forEach(l=>{x0=Math.min(x0,l.box[0]);y0=Math.min(y0,l.box[1]);x1=Math.max(x1,l.box[2]);y1=Math.max(y1,l.box[3]);});
  const m=4;
  return {paths,labels,leaders,total:tot,view:[x0-m,y0-m,x1-x0+2*m,y1-y0+2*m]};
}
function donutLegend(host,data){
  const tot=data.reduce((a,b)=>a+b[1],0)||1,R=62,r=41,cx=74,cy=76;let a=-Math.PI/2,s=`<svg width="156" height="152" viewBox="0 0 156 152">`;
  data.forEach((d,i)=>{const f=d[1]/tot,a2=a+f*2*Math.PI,big=f>.5?1:0,
    x1=cx+R*Math.cos(a),y1=cy+R*Math.sin(a),x2=cx+R*Math.cos(a2),y2=cy+R*Math.sin(a2),
    xi2=cx+r*Math.cos(a2),yi2=cy+r*Math.sin(a2),xi1=cx+r*Math.cos(a),yi1=cy+r*Math.sin(a);
    s+=`<path d="M${x1} ${y1} A${R} ${R} 0 ${big} 1 ${x2} ${y2} L${xi2} ${yi2} A${r} ${r} 0 ${big} 0 ${xi1} ${yi1} Z" fill="${colorFor(d[0],i)}"/>`;a=a2;});
  s+=`<text x="${cx}" y="${cy-1}" text-anchor="middle" font-size="19" font-weight="600" fill="#171a1e">${fmt(tot)}</text>`;
  s+=`<text x="${cx}" y="${cy+15}" text-anchor="middle" font-size="10" fill="#71767e" letter-spacing=".08em">TOTAL</text></svg>`;
  const leg='<div class="legend">'+data.map((d,i)=>`<span><i style="background:${colorFor(d[0],i)}"></i>${esc(d[0])} ${fmt(d[1])}</span>`).join('')+'</div>';
  host.innerHTML=`<div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">${s}<div style="flex:1;min-width:130px">${leg}</div></div>`;
}
function stacked(host,data){
  const tot=data.reduce((a,b)=>a+b[1],0)||1;let x=0,s=`<svg width="100%" height="20" viewBox="0 0 100 5" preserveAspectRatio="none">`;
  data.forEach((d,i)=>{const wd=d[1]/tot*100;s+=`<rect x="${x}" y="0" width="${wd}" height="5" fill="${colorFor(d[0],i)}"/>`;x+=wd;});
  host.innerHTML=s+'</svg><div class="legend">'+data.map((d,i)=>`<span><i style="background:${colorFor(d[0],i)}"></i>${esc(d[0])} — ${fmt(d[1])} (${Math.round(d[1]/tot*100)}%)</span>`).join('')+'</div>';
}
function mkTable(host,cols,rows,opts){
  opts=opts||{};let filter='',page=0,per=opts.per||40,sc=-1,sd=1,pf={};
  const wrap=document.createElement('div'),tools=document.createElement('div');tools.className='tools';
  const inp=document.createElement('input');inp.className='ui';inp.placeholder=opts.ph||('Search '+fmt(rows.length)+' rows');tools.appendChild(inp);
  const pills=document.createElement('div');pills.style.cssText='display:flex;gap:8px;flex-wrap:wrap';tools.appendChild(pills);
  const tbl=document.createElement('table'),pg=document.createElement('div');pg.className='pg';
  const scroll=document.createElement('div');scroll.className='tscroll';scroll.appendChild(tbl);
  wrap.append(tools,scroll,pg);host.innerHTML='';host.appendChild(wrap);
  function draw(){
    let r=rows;
    if(filter){const f=filter.toLowerCase();r=r.filter(x=>x.some(c=>String(c).toLowerCase().includes(f)));}
    for(const k in pf)if(pf[k]!=null)r=r.filter(x=>String(x[k])===String(pf[k]));
    if(sc>=0)r=r.slice().sort((a,b)=>{let A=a[sc],B=b[sc];if(typeof A==='number'&&typeof B==='number')return(A-B)*sd;return String(A).localeCompare(String(B))*sd;});
    const n=r.length,pages=Math.max(1,Math.ceil(n/per));page=Math.min(page,pages-1);
    let h='<thead><tr>'+cols.map((c,i)=>`<th data-i="${i}">${esc(c.t)}${sc===i?(sd>0?' ↑':' ↓'):''}</th>`).join('')+'</tr></thead><tbody>';
    r.slice(page*per,page*per+per).forEach(row=>{h+='<tr>'+cols.map((c,i)=>`<td title="${esc(String(row[i]==null?'':row[i]))}">${c.r?c.r(row[i],row):esc(row[i])}</td>`).join('')+'</tr>';});
    tbl.innerHTML=h+'</tbody>';
    tbl.querySelectorAll('th').forEach(th=>th.onclick=()=>{const i=+th.dataset.i;if(sc===i)sd=-sd;else{sc=i;sd=1;}draw();});
    pg.innerHTML=`<span>${fmt(n)} rows${(filter||Object.values(pf).some(v=>v!=null))?' · filtered':''}</span><button id="pp" ${page<=0?'disabled':''}>Prev</button><span>${page+1} / ${pages}</span><button id="pn" ${page>=pages-1?'disabled':''}>Next</button>`;
    const pp=pg.querySelector('#pp'),pn=pg.querySelector('#pn');if(pp)pp.onclick=()=>{page--;draw();};if(pn)pn.onclick=()=>{page++;draw();};
  }
  inp.oninput=()=>{filter=inp.value;page=0;draw();};draw();
  return {setColFilter:(ci,val)=>{pf[ci]=val;page=0;pills.innerHTML='';if(val!=null){const p=document.createElement('span');p.className='pill';p.textContent=cols[ci].t+': '+val+'  ✕';p.onclick=()=>{pf[ci]=null;pills.innerHTML='';draw();};pills.appendChild(p);}host.scrollIntoView({behavior:'smooth',block:'start'});draw();}};
}
window.__t={};
