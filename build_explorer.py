import json, pathlib

data = pathlib.Path("/home/user/rl-subdomain-tracker/samples_data.json").read_text().strip()

HTML = r'''<title>RL Data Samples</title>
<meta name="description" content="Browse public data samples, datasets, catalogs and benchmarks from 41 reinforcement-learning data companies.">
<style>
/* Layout: sticky filter toolbar over a single scrolling list grouped by company */
:root{
  --bg:#f7f6f3; --panel:#fff; --fg:#1b1a17; --muted:#6b6862; --line:#e4e1da;
  --accent:#b4531f; --accent-soft:#f0e3da;
  --file:#2f6f4f; --hosted:#3a5ca8; --sample:#8a5a16; --benchmark:#6b6862;
  --sans:"Inter",system-ui,sans-serif; --mono:"IBM Plex Mono",ui-monospace,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#17160f; --panel:#201e17; --fg:#eceae2; --muted:#9a968c; --line:#322f26;
  --accent:#e08a4f; --accent-soft:#2c2318;
  --file:#6cc79a; --hosted:#8fb0e8; --sample:#d8a860; --benchmark:#9a968c; color-scheme:dark;
}}
:root[data-theme="dark"]{
  --bg:#17160f; --panel:#201e17; --fg:#eceae2; --muted:#9a968c; --line:#322f26;
  --accent:#e08a4f; --accent-soft:#2c2318;
  --file:#6cc79a; --hosted:#8fb0e8; --sample:#d8a860; --benchmark:#9a968c; color-scheme:dark;
}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.45}
a{color:var(--accent)}
.wrap{max-width:960px;margin:0 auto;padding-inline:16px;padding-block:24px}
h1{font-size:1.5rem;margin:0 0 2px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:.85rem;margin:0 0 18px;max-width:60ch}
.bar{position:sticky;top:env(safe-area-inset-top,0px);background:var(--bg);padding-block:12px;z-index:5;border-bottom:1px solid var(--line)}
#q{width:100%;padding:10px 12px;font:inherit;border:1px solid var(--line);border-radius:9px;background:var(--panel);color:var(--fg)}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.chip{font:inherit;font-size:.8rem;padding:5px 11px;border:1px solid var(--line);border-radius:999px;background:var(--panel);color:var(--muted);cursor:pointer}
.chip[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);color:#fff}
.count{color:var(--muted);font-size:.8rem;margin:12px 2px;font-variant-numeric:tabular-nums}
.co{margin-top:18px}
.co h2{font-size:1.02rem;margin:0 0 4px;display:flex;align-items:baseline;gap:8px}
.co h2 a{font-weight:600;text-decoration:none}
.co h2 .n{color:var(--muted);font-size:.78rem;font-weight:400;font-family:var(--mono)}
.row{display:flex;gap:9px;align-items:baseline;padding:7px 0;border-top:1px solid var(--line)}
.k{flex:none;font-family:var(--mono);font-size:.62rem;text-transform:uppercase;letter-spacing:.06em;padding:3px 6px;border-radius:5px;background:var(--accent-soft);min-width:78px;text-align:center}
.k.file{color:var(--file)}.k.hosted{color:var(--hosted)}.k.sample{color:var(--sample)}.k.benchmark{color:var(--benchmark)}
.l{min-width:0;flex:1}
.l a{word-break:break-word;font-size:.9rem}
.t{display:block;color:var(--muted);font-size:.78rem}
.empty{color:var(--muted);padding:40px 0;text-align:center}
.foot{color:var(--muted);font-size:.76rem;margin-top:28px;border-top:1px solid var(--line);padding-top:12px;max-width:60ch}
</style>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=IBM+Plex+Mono:wght@400&display=swap">
<div class="wrap">
  <h1>RL Data Samples</h1>
  <p class="sub">Public data samples, datasets, catalogs and benchmarks found across 41 RL-data companies' live subdomains. Links only, nothing gated.</p>
  <div class="bar">
    <input id="q" type="search" placeholder="Search company, URL or text…" autocomplete="off">
    <div class="chips" id="chips">
      <button class="chip" data-k="all" aria-pressed="true">All</button>
      <button class="chip" data-k="file" aria-pressed="false">Files</button>
      <button class="chip" data-k="hosted" aria-pressed="false">Hosted datasets</button>
      <button class="chip" data-k="sample" aria-pressed="false">Sample pages</button>
      <button class="chip" data-k="benchmark" aria-pressed="false">Benchmarks</button>
    </div>
  </div>
  <div class="count" id="count"></div>
  <div id="list"></div>
  <p class="foot">Generated from the rl-subdomain-tracker crawl. Public pages only, robots.txt honoured. Several vendors keep their real samples behind request forms, which aren't included here.</p>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
const KIND={file:"FILE",hosted:"HOSTED",sample:"SAMPLE",benchmark:"BENCHMARK"};
const rows=JSON.parse(document.getElementById("data").textContent);
const list=document.getElementById("list"),count=document.getElementById("count"),q=document.getElementById("q");
let kind="all",term="";
function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}
function label(u){try{const x=new URL(u);return x.hostname.replace(/^www\./,"")+x.pathname.replace(/\/$/,"")}catch(e){return u}}
function render(){
  const f=rows.filter(r=>(kind==="all"||r.k===kind)&&(!term||((r.c+" "+r.u+" "+r.t).toLowerCase().includes(term))));
  count.textContent=f.length+" link"+(f.length===1?"":"s")+" · "+new Set(f.map(r=>r.c)).size+" companies";
  if(!f.length){list.innerHTML='<p class="empty">No matching links.</p>';return}
  const by={};f.forEach(r=>(by[r.c]=by[r.c]||[]).push(r));
  list.innerHTML=Object.keys(by).sort().map(c=>{
    const site="https://"+c.replace(/^labs\./,"");
    const items=by[c].map(r=>'<div class="row"><span class="k '+r.k+'">'+KIND[r.k]+'</span><span class="l"><a href="'+esc(r.u)+'" target="_blank" rel="noopener">'+esc(label(r.u))+'</a>'+(r.t&&r.t!=="sitemap"?'<span class="t">'+esc(r.t)+'</span>':'')+'</span></div>').join("");
    return '<section class="co"><h2><a href="'+esc(site)+'" target="_blank" rel="noopener">'+esc(c)+'</a><span class="n">'+by[c].length+'</span></h2>'+items+'</section>';
  }).join("");
}
document.getElementById("chips").addEventListener("click",e=>{
  const b=e.target.closest(".chip");if(!b)return;
  kind=b.dataset.k;[...e.currentTarget.children].forEach(c=>c.setAttribute("aria-pressed",c===b));render();
});
q.addEventListener("input",()=>{term=q.value.trim().toLowerCase();render();});
render();
</script>
'''

out = HTML.replace("__DATA__", data)
pathlib.Path("/home/user/rl-subdomain-tracker/explorer.html").write_text(out)
print("size", len(out), "| data rows embedded:", data.count('"u":'))
