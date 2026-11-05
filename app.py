#!/usr/bin/env python3
"""
FortiSIEM Log Terminal - local only, stdlib only, no cloud upload.
Usage:
  python app.py                -> web terminal at http://127.0.0.1:8765
  python app.py --cli <file>   -> interactive troubleshooting terminal
  python app.py --stats <file> -> one-shot stats
  python app.py --port 8765
"""
import base64, collections, gzip, html, io, json, os, re, sys, tarfile, threading, time, zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

BASE = Path(__file__).resolve().parent
UPLOADS = BASE / "uploads"
UPLOADS.mkdir(exist_ok=True)
INDEX = UPLOADS / "index.json"
MAX_BYTES = 200 * 1024 * 1024  # 200MB per request (AO tar bundles are ~60MB)
PORT_DEFAULT = 8765

SEV_RE = re.compile(r'\b(CRITICAL|FATAL|ERROR|ERR|FAIL(?:URE|ED)?|WARN(?:ING)?|INFO|DEBUG|NOTICE|ALERT|SEV\s*=\s*[1-5])\b', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TIME_RE = re.compile(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')
HOST_RE = re.compile(r'(?:host|hostname|src|dst|device|sensor|collector)[=:\s]+([A-Za-z0-9._\-]+)', re.I)

def classify(line):
    m = SEV_RE.search(line)
    if not m: return "UNKNOWN"
    s = m.group(1).upper()
    if s.startswith("SEV"): 
        return { "SEV = 1":"CRITICAL","SEV = 2":"ERROR","SEV = 3":"WARN","SEV = 4":"INFO","SEV = 5":"DEBUG"}.get(s,"UNKNOWN")
    if s in ("CRITICAL","FATAL","ALERT"): return "CRITICAL"
    if s in ("ERROR","ERR") or "FAIL" in s: return "ERROR"
    if "WARN" in s: return "WARN"
    if s == "NOTICE": return "INFO"
    return s

def norm_msg(line):
    s = TIME_RE.sub("<TIME>", line)
    s = IP_RE.sub("<IP>", s)
    s = re.sub(r'\b[0-9a-fA-F]{8,}\b', "<ID>", s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s[:220]

def parse_text(text, fname):
    lines = text.splitlines()
    entries = []
    for i, raw in enumerate(lines, 1):
        if not raw.strip(): continue
        entries.append({
            "n": i, "file": fname, "text": raw.rstrip(),
            "sev": classify(raw),
            "time": (TIME_RE.search(raw).group(1) if TIME_RE.search(raw) else ""),
            "ips": IP_RE.findall(raw),
            "kv": dict(KV_RE.findall(raw)),
            "norm": norm_msg(raw),
        })
    return entries

def read_upload(name, data_bytes):
    name = Path(name).name or "upload.log"
    low = name.lower()
    if low.endswith((".tar",".tgz",".tar.gz",".tar.bz2")):
        out=[]
        try:
            with tarfile.open(fileobj=io.BytesIO(data_bytes)) as t:
                for m in t.getmembers():
                    if m.isfile():
                        out.append(f"===== {m.name} ({m.size} bytes) =====")
                        # only inline small text logs for search; large analysis is via analyze_ao.py
                        if m.size < 200000 and any(x in m.name.lower() for x in (".log",".txt",".out","messages","dmesg","top","df","phstatus")):
                            f=t.extractfile(m)
                            if f: out.append(f.read().decode("utf-8","replace")[:50000])
        except Exception as e: return name, f"[tar error: {e}]"
        return name, "\n".join(out)
    if name.lower().endswith(".gz"):
        try: data_bytes = gzip.decompress(data_bytes)
        except Exception as e: return name, f"[gzip error: {e}]"
    if name.lower().endswith(".zip"):
        out = []
        try:
            with zipfile.ZipFile(io.BytesIO(data_bytes)) as z:
                for info in z.infolist():
                    if not info.is_dir():
                        out.append(f"===== {info.filename} =====\n" + z.read(info.filename).decode("utf-8","replace"))
        except Exception as e: return name, f"[zip error: {e}]"
        return name, "\n".join(out)
    return name, data_bytes.decode("utf-8","replace")

def load_index():
    try: return json.loads(INDEX.read_text(encoding="utf-8"))
    except Exception: return []

def save_index(records):
    INDEX.write_text(json.dumps(records, indent=2), encoding="utf-8")

def get_entries(fname=None):
    # in-memory cache rebuilt from files on disk
    all_e = []
    for p in sorted(UPLOADS.iterdir()):
        if p.name == "index.json" or p.is_dir(): continue
        if fname and p.name != fname: continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception: continue
        all_e.extend(parse_text(txt, p.name))
    return all_e

def stats_for(entries):
    sev = collections.Counter(e["sev"] for e in entries)
    ips = collections.Counter(ip for e in entries for ip in e["ips"])
    msgs = collections.Counter(e["norm"] for e in entries if e["sev"] in ("ERROR","CRITICAL","WARN"))
    times = [e["time"] for e in entries if e["time"]]
    return {
        "total": len(entries), "by_sev": dict(sev),
        "top_ips": ips.most_common(15),
        "top_errors": msgs.most_common(15),
        "first_seen": times[0] if times else "", "last_seen": times[-1] if times else "",
    }

PAGE = r"""<!doctype html><meta charset=utf-8><title>FortiSIEM Log Terminal</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
body{background:#0b0f14;color:#d6deeb;font-family:Consolas,Menlo,monospace;margin:0;padding:16px}
h1{font-size:18px;margin:0 0 4px} .sub{color:#8aa0b8;font-size:12px;margin-bottom:14px}
#drop{border:2px dashed #36506b;border-radius:10px;padding:28px;text-align:center;cursor:pointer;background:#101823}
#drop.over{border-color:#3fb950;background:#12231a}
input,select,button{background:#16202e;color:#d6deeb;border:1px solid #36506b;border-radius:6px;padding:8px 10px}
button{cursor:pointer;background:#1f6feb;border-color:#1f6feb}
.row{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
.grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px} @media(max-width:900px){.grid{grid-template-columns:1fr}}
.card{background:#101823;border:1px solid #26374a;border-radius:10px;padding:12px;min-height:120px}
.card h3{margin:0 0 8px;font-size:13px;color:#8aa0b8} .card div{font-size:12px;white-space:pre-wrap;word-break:break-word}
#out{white-space:pre-wrap;font-size:12px;line-height:1.5;max-height:55vh;overflow:auto;background:#070b10;border:1px solid #26374a;border-radius:10px;padding:12px}
.ERR{color:#ff7b72}.CRITICAL{color:#ff4d4d;font-weight:bold}.WARN{color:#d29922}.INFO{color:#8aa0b8}
small{color:#8aa0b8}
</style>
<body>
<h1>FortiSIEM Log Terminal</h1>
<div class=sub>Local only - files stay in <b>uploads/</b> on this PC. Nothing is sent to the cloud. Drag FortiSIEM / AO logs here to troubleshoot.</div>
<div id=drop>Drag &amp; drop .log .txt .csv .gz .zip .tar .tgz here, or click to browse<br><small>AO .tar bundles auto-extract + analyze backend/appsvr/system, tag restarts [RESTART-ALERT], label CRITICAL, list fixes. 200 MB per batch</small><input id=file type=file multiple hidden accept=".log,.txt,.csv,.gz,.zip,.tar,.tgz,.tar.gz"></div>
<div class=row>
 <input id=q placeholder="Search text, IP, host, event id... (e.g. 10.0.0.5 or auth failed)" size=46>
 <select id=sev><option value="">All severities</option><option>CRITICAL</option><option>ERROR</option><option>WARN</option><option>INFO</option><option>UNKNOWN</option></select>
 <select id=selFile><option value="">All files</option></select>
 <button onclick="run()">Search</button>
 <button onclick="exportTxt()">Export filtered (.txt)</button>
 <button onclick="report()">Incident report (.md)</button>
</div>
<div class=grid>
 <div class=card><h3>STATS</h3><div id=stats>Upload a log to begin.</div></div>
 <div class=card><h3>TOP IPs</h3><div id=ips></div></div>
 <div class=card><h3>TOP ERRORS / REPEATED MESSAGES</h3><div id=errs></div></div>
</div>
<div class=row><small id=meta></small></div>
<div id=out>Terminal ready. Uploaded lines will appear here, colour-coded by severity.</div>
<script>
const drop=document.getElementById('drop'), file=document.getElementById('file');
drop.onclick=()=>file.click();
drop.ondragover=e=>{e.preventDefault();drop.classList.add('over')};
drop.ondragleave=()=>drop.classList.remove('over');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('over');upload(e.dataTransfer.files)};
file.onchange=()=>upload(file.files);
function b64(f){return new Promise(r=>{const fr=new FileReader();fr.onload=()=>r(fr.result.split(',')[1]);fr.readAsDataURL(f)})}
async function upload(files){
  const out=document.getElementById('out'); out.textContent='Uploading '+files.length+' file(s)...';
  const payload={files:[]};
  for(const f of files){ payload.files.push({name:f.name, data_b64:await b64(f)}) }
  const t0=Date.now();
  const r=await fetch('/api/upload',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const j=await r.json(); out.textContent=j.msg+'  ('+((Date.now()-t0)/1000).toFixed(1)+'s)';
  refreshFiles(); run();
}
async function refreshFiles(){
  const j=await (await fetch('/api/files')).json();
  const s=document.getElementById('selFile'); s.innerHTML='<option value="">All files</option>'+j.files.map(f=>`<option>${f}</option>`).join('');
}
async function run(){
  const q=document.getElementById('q').value, sev=document.getElementById('sev').value, fn=document.getElementById('selFile').value;
  const j=await (await fetch(`/api/search?q=${encodeURIComponent(q)}&sev=${sev}&file=${encodeURIComponent(fn)}`)).json();
  document.getElementById('out').innerHTML=j.entries.map(e=>`<div><span class="${e.sev}">${e.n} [${e.sev}]</span> ${esc(e.text)}</div>`).join('')||'No matches.';
  document.getElementById('meta').textContent=j.entries.length+' matching line(s) of '+j.total+' total';
  const s=j.stats;
  document.getElementById('stats').textContent=`Total: ${s.total}\nBy severity: ${JSON.stringify(s.by_sev)}\nFirst: ${s.first_seen}\nLast: ${s.last_seen}`;
  document.getElementById('ips').textContent=s.top_ips.map(x=>x.join('  x')).join('\n')||'-';
  document.getElementById('errs').textContent=s.top_errors.map(x=>x.join('  x')).join('\n\n')||'-';
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function dl(name,text){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([text],{type:'text/plain'}));a.download=name;a.click()}
async function exportTxt(){
  const q=document.getElementById('q').value, sev=document.getElementById('sev').value, fn=document.getElementById('selFile').value;
  const j=await (await fetch(`/api/search?q=${encodeURIComponent(q)}&sev=${sev}&file=${encodeURIComponent(fn)}`)).json();
  dl('filtered-log.txt', j.entries.map(e=>e.text).join('\n'));
}
async function report(){
  const fn=document.getElementById('selFile').value;
  const j=await (await fetch(`/api/search?q=&sev=&file=${encodeURIComponent(fn)}`)).json(); const s=j.stats;
  dl('incident-report.md', `# FortiSIEM Incident Report\nGenerated: ${new Date().toISOString()}\n\n## Summary\nTotal lines: ${s.total}\nBy severity: ${JSON.stringify(s.by_sev)}\nFirst seen: ${s.first_seen}\nLast seen: ${s.last_seen}\n\n## Top IPs\n${s.top_ips.map(x=>'- '+x.join(' x')).join('\n')}\n\n## Top errors\n${s.top_errors.map(x=>'- '+x.join(' x')).join('\n')}\n\n## Next steps\n1. Check top IPs against asset inventory / threat intel.\n2. Pivot on top error messages in FortiSIEM for same time window.\n3. Preserve original uploads/ files as evidence.\n`);
}
refreshFiles();
</script></body>
"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/": 
            b = PAGE.encode(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
        if u.path == "/api/files":
            files = sorted(p.name for p in UPLOADS.iterdir() if p.is_file() and p.name!="index.json")
            return self.send_json({"files":files})
        if u.path == "/api/report":
            qs = parse_qs(u.query); fn = qs.get("file",[""])[0]
            candidates = sorted(UPLOADS.glob("*AO*REPORT*.md")) + sorted(UPLOADS.glob("*AO_ANALYSIS_REPORT.md"))
            if fn:
                candidates = [p for p in candidates if fn.split(".")[0] in p.name] or candidates
            if candidates:
                txt = candidates[-1].read_text(encoding="utf-8", errors="replace")
                b = txt.encode(); self.send_response(200); self.send_header("Content-Type","text/plain; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
            return self.send_json({"error":"no report yet - upload a .tar AO bundle first"},404)
        if u.path == "/api/search":
            qs = parse_qs(u.query); q = qs.get("q",[""])[0].lower(); sev = qs.get("sev",[""])[0]; fn = qs.get("file",[""])[0] or None
            entries = get_entries(fn)
            total = len(entries)
            if sev: entries = [e for e in entries if e["sev"]==sev]
            if q: entries = [e for e in entries if q in e["text"].lower() or q in str(e["kv"]).lower()]
            return self.send_json({"entries":entries[:5000],"total":total,"stats":stats_for(get_entries(fn))})
        self.send_response(404); self.end_headers()
    def do_POST(self):
        if urlparse(self.path).path != "/api/upload": self.send_response(404); self.end_headers(); return
        length = int(self.headers.get("Content-Length",0))
        if length > MAX_BYTES: return self.send_json({"ok":False,"msg":"Too large (>50MB). Split the log."},413)
        try: payload = json.loads(self.rfile.read(length))
        except Exception as e: return self.send_json({"ok":False,"msg":str(e)},400)
        saved = []
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-")
        for f in payload.get("files",[]):
            try:
                raw = base64.b64decode(f.get("data_b64",""))
                name, text = read_upload(f.get("name","upload.log"), raw)
                safe = re.sub(r'[^A-Za-z0-9._\-]', '_', name)
                dest = UPLOADS / (stamp + safe)
                # avoid overwrite
                i=1
                while dest.exists(): dest = UPLOADS / f"{stamp}{i}_{safe}"; i+=1
                dest.write_text(text, encoding="utf-8", errors="replace")
                entry={"name":dest.name,"lines":text.count(chr(10))+1,"bytes":len(text.encode('utf-8'))}
                # AO tar bundle: extract + auto-analyze backend/appsvr/system, generate report
                orig_low = (f.get("name","") or "").lower()
                if orig_low.endswith((".tar",".tgz",".tar.gz",".tar.bz2")):
                    try:
                        sys.path.insert(0, str(BASE))
                        import analyze_ao as AO
                        ext_dir = UPLOADS / (stamp + "extracted")
                        # save original tar and extract from it
                        tar_path = UPLOADS / (stamp + "original.tar")
                        tar_path.write_bytes(raw)
                        AO.extract_archive(tar_path, ext_dir)
                        root = ext_dir / "AOLogs" if (ext_dir/"AOLogs").exists() else ext_dir
                        res = AO.analyze(root)
                        md = AO.render_md(orig_low, res)
                        report_path = UPLOADS / (stamp + "AO_ANALYSIS_REPORT.md")
                        report_path.write_text(md, encoding="utf-8")
                        crit = sum(1 for i in res["issues"] if i["sev"]=="CRITICAL")
                        entry["ao_report"]={"path":report_path.name,"issues":len(res["issues"]),"critical":crit,"restarts":len(res["restarts"]),"files":res["total_files"]}
                    except Exception as ae:
                        entry["ao_report_error"]=str(ae)
                saved.append(entry)
            except Exception as e: saved.append({"name":f.get("name"),"error":str(e)})
        rec = load_index(); rec.append({"time":datetime.now().isoformat(),"files":saved}); save_index(rec)
        return self.send_json({"ok":True,"msg":"Uploaded: "+", ".join(s.get("name","?") for s in saved),"files":saved})

def cli(files):
    entries=[]
    for f in files:
        p=Path(f)
        if not p.exists(): print(f"Not found: {f}"); continue
        name, text = read_upload(p.name, p.read_bytes())
        entries.extend(parse_text(text, name))
    if not entries: print("No lines parsed."); return
    def show_stats():
        s=stats_for(entries)
        print(f"Total: {s['total']}  Sev: {s['by_sev']}  {s['first_seen']} -> {s['last_seen']}")
        print("Top IPs:"); [print(" ",ip,"x",c) for ip,c in s["top_ips"][:10]]
        print("Top errors:"); [print(" ",m,"x",c) for m,c in s["top_errors"][:10]]
    show_stats()
    print("Terminal ready. Commands: help | stats | search <term> | errors | ips | export <path> | quit")
    while True:
        try: cmd=input("\nfortisiem> ").strip()
        except EOFError: break
        if not cmd: continue
        parts=cmd.split(maxsplit=1); c=parts[0].lower(); arg=parts[1] if len(parts)>1 else ""
        if c in ("quit","exit"): break
        elif c=="help": print("stats | search <term> | errors | ips | export <path> | quit")
        elif c=="stats": show_stats()
        elif c=="errors": [print(e["text"]) for e in entries if e["sev"] in ("ERROR","CRITICAL")][:200]
        elif c=="ips": [print(ip,"x",n) for ip,n in stats_for(entries)["top_ips"]]
        elif c=="search": [print(e["text"]) for e in entries if arg.lower() in e["text"].lower()][:500] or print("(no matches)")
        elif c=="export" and arg: Path(arg).write_text("\n".join(e["text"] for e in entries), encoding="utf-8"); print(f"Wrote {arg}")
        else: print("Unknown. Type help.")

def main():
    args=sys.argv[1:]
    if "--cli" in args:
        files=[a for a in args if a not in ("--cli",) and not a.startswith("--")]
        return cli(files)
    if "--stats" in args:
        files=[a for a in args if a not in ("--stats",) and not a.startswith("--")]
        entries=[]
        for f in files:
            name,text=read_upload(Path(f).name, Path(f).read_bytes()); entries.extend(parse_text(text,name))
        print(json.dumps(stats_for(entries),indent=2)); return
    port=PORT_DEFAULT
    if "--port" in args: port=int(args[args.index("--port")+1])
    print(f"FortiSIEM Log Terminal: http://127.0.0.1:{port}  (local only, uploads in {UPLOADS})")
    print("Press Ctrl+C to stop.")
    ThreadingHTTPServer(("127.0.0.1",port), H).serve_forever()

if __name__=="__main__": main()
