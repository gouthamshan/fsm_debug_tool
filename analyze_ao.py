#!/usr/bin/env python3
"""
AO Log Analyzer - FortiSIEM
Usage:
  python3 analyze_ao.py <file.tar|.tar.gz|.tgz|.zip> [--out DIR] [--name LABEL]
  python3 analyze_ao.py <extracted_dir> [--out DIR]
Outputs: <out>/AO_ANALYSIS_REPORT.md, .txt, .json plus console summary
Detects: backend/appsvr/system/postgres process groups, errors, CRITICAL,
restarts ([RESTART-ALERT]), crashes/minidumps, disk/memory pressure.
Stdlib only.
"""
import collections, gzip, io, json, os, re, sys, tarfile, zipfile
from pathlib import Path

CRITICAL_PATTERNS = [
    ("CRITICAL", re.compile(r'\bCRITICAL\b|FATAL|panic|segfault|core dump|Segmentation fault', re.I)),
    ("MINIDUMP/CRASH", re.compile(r'minidump|crash|segfault|core dump', re.I)),
    ("TCMALLOC HEAP CORRUPTION", re.compile(r'tcmalloc|Attempt to free invalid pointer|invalid pointer', re.I)),
    ("JEDIS POOL NOT OPEN", re.compile(r'JedisConnectionException|Pool not open|Could not get a resource from the pool|RedisSubscriber|PH_APPSERVER_REDIS_ERROR', re.I)),
    ("LOOKUP TABLE CANNOT LOAD", re.compile(r'PH_LOOKUP_TABLE_CANNOT_LOAD_DATA|Failed to load data from Nodejs/Redis|lookup table.*not found|Failed to load.*lookup', re.I)),
    ("FORTIGUARD FEED LOAD", re.compile(r'PH_SYS_FORTIGUARD_(MAL_DOMAIN|BLOCKED_URL|BLOCKED_IP)', re.I)),
    ("SHARED BUFFER DROP", re.compile(r'PH_DROP_EVENT_FROM_SHARED_BUFFER|Events delay', re.I)),
    ("GLASSFISH / APPSVR DOWN", re.compile(r'attempt to connect to 127\.0\.0\.1:8282|GlassFish.*shutdown|EJB Timer Service shutdown', re.I)),
    ("OOM / MEMORY KILLED", re.compile(r'out of memory|\bOOM\b|Killed process|Cannot allocate memory', re.I)),
    ("DISK FULL", re.compile(r'no space left|disk full|quota exceeded|too many open files', re.I)),
    ("DB/CONNECTION DOWN", re.compile(r'database.*(down|failed|unreachable)|postgres.*(down|failed|fatal)|connection refused|Connection reset by peer', re.I)),
    ("SERVICE FAILED", re.compile(r'service.*failed|Failed to start|failed to connect|unable to connect', re.I)),
]
MAX_LINES_PER_FILE = 200000
MAX_RESTARTS_TOTAL = 500
RESTART_RE = re.compile(r'\b(restart\w*|starting|started|shutdown|shutting down|stopped|reboot\w*|service.*up|listening|ready|init.*complete|phoenix.*start|worker.*start)\b', re.I)
SEV_RE = re.compile(r'\b(CRITICAL|FATAL|ERROR|ERR|FAIL(?:URE|ED)?|WARN(?:ING)?|INFO|DEBUG)\b', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TIME_RE = re.compile(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[^\s]*|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{2}/\d{2}/\d{4}[^\s]*|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)')

FIXES = [
    (r'lookup table.*cannot load|failed to load data from nodejs|lookup.*not found', "LOOKUP TABLE CANNOT LOAD", "CRITICAL for rule triggering: phRuleWorker/phRuleMaster cannot load lookup tables from Node/Redis (PH_LOOKUP_TABLE_CANNOT_LOAD_DATA). Rules needing that table cannot evaluate. Fix: fix Redis/Node path first (see JEDIS/REDIS fixes), check pm2 access log for lookupTables GET sizes and lookupTableNames polling, verify Node REST API is up (127.0.0.1:3000) and Redis 6666 is reachable, then restart phRuleWorker to reload tables. If it persists with Redis healthy, it is a ph* parsing bug for large tables - TAC with table name and size."),
    (r'fortiguard.*(mal_domain|blocked_url|blocked_ip)|ph_sys_fortiguard', "FORTIGUARD FEED LOAD - 87MB PER CYCLE", "CRITICAL load: phRuleWorker loads FortiGuard malware domain ~61MB + blocked URL ~25MB + blocked IP ~1.8MB = ~87MB per cycle via pm2 Node namedValue API, repeated many times. This blocks phRuleWorker (CPU 962%, RES 3.4GB), fills shared buffer, drops events. Fix: check feed reload frequency in pm2 access.log, tune reload interval / cache, split malware-domain rules from main rule thread, monitor access.log GET sizes for PH_SYS_FORTIGUARD_* - if it reloads every few minutes, that is the block."),
    (r'drop_event_from_shared_buffer|events delay', "SHARED BUFFER DROP - EVENTS LOST", "CRITICAL for incidents: PH_DROP_EVENT_FROM_SHARED_BUFFER, Events delay - phRuleWorker is too busy/delayed to read SSS shared buffer, events are dropped, rules never see them, incidents do not trigger. Fix: reduce lookup/FortiGuard load (above), fix Redis, check SSS store (system/sss writer position), tune writer_buffer and phRuleWorker threads, monitor drop count as rule-health metric."),
    (r'jedis|pool not open|redis.*pool|ph_appsv|redissubscriber', "JEDIS POOL NOT OPEN - RULES STOP", "CRITICAL for rule triggering: GlassFish Jedis pool is closed, AppServer cannot get Redis, FSMRuleService/IncidentProcessor fail, rules stop triggering. First failure is usually 'Unexpected end of stream' in RedisSubscriber.subscribe() when Redis drops. Fix: fix Redis root cause first (see REDIS fix), then restart GlassFish/AppSvr to recreate pool - restarting is only a workaround. Check Jedis pool config (maxTotal, testOnBorrow, timeBetweenEviction), Redis maxclients, and that Redis does not restart/drop connections. Monitor server.log for JedisConnectionException count after restart - if it climbs again within hours, pool will close again."),
    (r'tcmalloc|attempt to free invalid pointer|segfault at 0.*tcmalloc|segfault at 58', "TCMALLOC HEAP CORRUPTION -> SIGSEGV/SIGABRT", "CRITICAL backend crash: libtcmalloc.so.4.5.9 heap corruption (invalid free) causes SIGABRT, then SIGSEGV at 0x0 / 0x58 at same offset (base+0x28000) in phDataManager, phParser, phAgentManager on both Worker and Super, version 7.6.1.0753. This is a vendor build bug, not a config issue - restarting only reloads the corrupted heap. Fix: TAC case with minidumps + dmesg segfault times + AO_VERSION, request patched build / tcmalloc fix, check for known issue in 7.6.1.0753. Do not raise memory limits as a fix."),
    (r'glassfish|8282|appsvr.*down|ejb.*shutdown', "GLASSFISH / APPSVR DOWN", "Fix: check GlassFish domain1 service, port 8282 listening, appsvr/server.log for shutdown hook vs crash, java heap (AppSvr RES 5 GB on Super). Restart only via supported method, then verify FSMRuleServiceBean JNDI is up and Jedis pool is open."),
    (r'minidump|segfault|core dump|crash', "CRASH / MINIDUMP", "A worker process crashed (minidump present). Fix: correlate crash time in phoenix.log with messages/dmesg for OOM/segfault; check phstatus for memory pressure; restart the specific ph* worker via phxctl, then watch phoenix.log for repeat crashes. If repeatable, collect the minidump + exact version (AO_VERSION) for Fortinet TAC."),
    (r'out of memory|\bOOM\b|killed process|cannot allocate', "OUT OF MEMORY", "Kernel/process OOM. Fix: check phstatus/top/vmstat for swap use; identify top RES process (often phDataManager/phRuleWorker); increase RAM/swap on this worker, reduce EPS/rules load, check for memory leak (same worker RES climbing across phstatus snapshots), restart worker if stuck."),
    (r'no space left|disk full|quota', "DISK FULL", "Disk full will stop logging and DB writes. Fix: df -h (see report Disk section); /data at 80% and /archive at 86% in this bundle - plan archiving/deletion; clear /tmp, rotated logs, ansible tgz bundles; never delete /data online DB directly - use FortiSIEM archive/retention policy."),
    (r'connection refused|connection reset|unable to connect|failed to connect|database.*fail|postgres.*fail', "CONNECTION / DB FAILURE", "Fix: check service status (postgres, redis 6379/6666, clickhouse, httpd); test connectivity to supervisor/SM04, DB host and DNS (see phshowVersion IP/DNS); check firewall/policy denies in messages; restart the failed service only after confirming config (phoenix_config) is intact."),
    (r'authentication failed|login failure|brute', "AUTH FAILURES", "Fix: identify src IP in top IPs; check if collector/user lockout; verify NTP/DNS; block/allow list at firewall if hostile."),
    (r'restart|starting|shutdown|stopped|reboot', "RESTART / START-STOP", "Tagged [RESTART-ALERT] in report. Fix: confirm if restart was planned (upgrade/ansible) or unexpected; check messages around that timestamp for OOM, segfault, or admin action; if unexpected and repeated, treat as crash (see MINIDUMP fix)."),
    (r'error|failed|exception|traceback', "GENERAL ERROR", "Fix: note top repeated message + first/last seen; pivot in FortiSIEM on same host/time; check related process status in phstatus; if error stops after a restart, monitor EPS and worker CPU."),
    (r'timeout|timed out', "TIMEOUT", "Fix: check load average and CPU in phstatus (high CPU + iowait = disk/DB bottleneck); check /data disk % and clickhouse/redis health; reduce rule/query load or scale worker."),
    (r'permission|denied', "PERMISSION / DENIED", "Fix: check file ownership/SELinux (messages), license (license.txt), and policy denies; verify services run as correct user after upgrade."),
    (r'redis', "REDIS", "Fix: check redis_info.out (used_memory, evicted_keys, maxmemory), 6666.log for eviction/OOM warnings; if evictions high, raise maxmemory or reduce ph* cache load; restart redis only in maintenance window."),
    (r'clickhouse|broken part', "CLICKHOUSE", "Fix: check clickhouse databases/tables output, broken-parts config, disk space on /data; run clickhouse-client SYSTEM checks per Fortinet guide; do not delete parts manually - engage TAC if parts are broken."),
    (r'pm2|node|rest api', "APPSVR / NODE REST API", "Fix: check pm2 status + FortiSIEM-Node-REST-API error logs; restart pm2 app (pm2 restart); check Node memory (phstatus Node.js-pm2) and httpd ssl_error_log for upstream failures."),
    (r'httpd|apache|ssl.*error', "HTTPD / APACHE", "Fix: check ssl_error_log and ssl_access_log for 5xx spikes by IP/URI; verify cert expiry (phConfigLocalCerts); restart httpd only if config test passes (httpd -t)."),
]

def fix_for(text):
    low = text.lower()
    for pat, title, fix in FIXES:
        if re.search(pat, low):
            return title, fix
    return "GENERAL ERROR", "Fix: pivot in FortiSIEM on host + time window, check phstatus for that process, and monitor after any restart."

def classify(relpath):
    p = relpath.replace("\\","/").lower()
    if p.startswith("backend/") or "/backend/" in p or p.startswith("aologs/backend"): return "backend"
    if p.startswith("appsvr/") or "/appsvr/" in p or "/pm2/" in p or "node-rest" in p or "glassfish" in p: return "appsvr"
    if p.startswith("postgres/") or "/postgres/" in p: return "postgres"
    if p.startswith("system/") or "/system/" in p or p.startswith("configcollection/") or "/configcollection/" in p: return "system"
    if p.startswith("upgrade/") or "/upgrade/" in p: return "upgrade"
    if p.startswith("tmp/") or "/tmp/" in p: return "tmp"
    return "other"

def is_logfile(name):
    n = name.lower()
    if any(n.endswith(x) for x in (".p12",".minidump",".tgz",".tar",".zip",".jpg",".png")): return False
    if ".minidump" in n: return False
    return any(x in n for x in (".log",".txt",".out","messages","dmesg","top","df","vmstat","phstatus","sss","sa0","license","version","access","combined","error")) or n.endswith(("top","df","vmstat","phstatus","sss","messages"))

def iter_lines(path: Path):
    # streaming: handle .gz, .gz.gz, plain - cap lines to avoid huge pm2 access logs blowing RAM/time
    opener = open(path, "rb")
    raw = opener.read(2); opener.close()
    if raw == b'\x1f\x8b':
        # handle double-gzip by wrapping: gzip.open handles one layer; loop via BytesIO
        import gzip as _gz
        f = path
        # detect double gz by peeking decompressed magic is hard; use layered approach with limit
        stream = _gz.open(f, "rt", encoding="utf-8", errors="replace")
        count=0
        try:
            for line in stream:
                count+=1
                if count>MAX_LINES_PER_FILE: break
                yield line.rstrip("\n")
                # if this was .gz.gz, first layer yields binary-ish? gzip rt will error on second layer; fallback below
        except Exception:
            # double-gz fallback: decompress in chunks, capped
            try:
                data=b""
                with _gz.open(f,"rb") as g1:
                    chunk=g1.read(5*1024*1024)
                    data=chunk
                if data[:2]==b'\x1f\x8b':
                    import io as _io
                    with _gz.GzipFile(fileobj=_io.BytesIO(data)) as g2:
                        txt=g2.read().decode("utf-8","replace")
                    for line in txt.splitlines()[:MAX_LINES_PER_FILE]:
                        yield line
            except Exception:
                pass
        finally:
            try: stream.close()
            except: pass
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i>=MAX_LINES_PER_FILE: break
            yield line.rstrip("\n")

def extract_archive(src: Path, dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        return src
    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z: z.extractall(dest)
        return dest
    # tar variants
    with tarfile.open(src) as t:
        members=[m for m in t.getmembers() if '..' not in m.name and not m.name.startswith('/')]
        t.extractall(dest, members=members)
    return dest

def norm(line):
    s = TIME_RE.sub("<TIME>", line)
    s = IP_RE.sub("<IP>", s)
    s = re.sub(r'\b[0-9a-fA-F]{8,}\b', "<ID>", s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s[:240]

def severity(line):
    m = SEV_RE.search(line)
    return m.group(1).upper() if m else "UNKNOWN"

def validate_redis(root: Path):
    """Validate 6666.conf + redis_info.out + redis log counts. Returns dict for report."""
    out={"conf":{},"info":{},"log_counts":{},"notes":[]}
    for conf in root.rglob("6666.conf.gz"):
        try:
            import gzip as _gz
            txt=_gz.decompress(conf.read_bytes()).decode(errors="replace")
            out["conf"][conf.relative_to(root).as_posix()]=txt[:2000]
            if "maxclients" not in txt: out["notes"].append(f"{conf} has NO maxclients directive - default 10000 applies")
            if "timeout" not in txt: out["notes"].append(f"{conf} has NO timeout directive - clients never idle-timeout")
        except Exception as e: out["notes"].append(str(e))
    for infof in root.rglob("redis_info.out.gz"):
        try:
            import gzip as _gz
            txt=_gz.decompress(infof.read_bytes()).decode(errors="replace")
            kv={}
            for line in txt.splitlines():
                if ":" in line and not line.startswith("#"):
                    k,v=line.split(":",1); kv[k.strip()]=v.strip()
            keep={k:kv.get(k) for k in ("connected_clients","maxclients","rejected_connections","total_connections_received","used_memory_human","maxmemory_human","role","master_link_status","connected_slaves","evicted_keys","total_error_replies","uptime_in_seconds")}
            out["info"][infof.relative_to(root).as_posix()]=keep
        except Exception as e: out["notes"].append(str(e))
    for logf in root.rglob("6666.log.gz"):
        try:
            import gzip as _gz
            txt=_gz.decompress(logf.read_bytes()).decode(errors="replace")
            out["log_counts"][logf.relative_to(root).as_posix()]={
                "max_clients_reached": len(re.findall(r'max number of clients reached', txt, re.I)),
                "ready_to_accept": len(re.findall(r'Ready to accept connections', txt)),
                "sigterm_shutdown": len(re.findall(r'Received SIGTERM|User requested shutdown', txt)),
                "replica_lost": len(re.findall(r'Connection with replica .* lost|Connection with master lost', txt)),
                "full_resync": len(re.findall(r'Full resync from master', txt)),
                "partial_resync_fail": len(re.findall(r'Partial resynchronization not possible', txt)),
            }
        except Exception as e: out["notes"].append(str(e))
    return out

def analyze(root: Path):
    files = [p for p in root.rglob("*") if p.is_file()]
    by_proc = collections.defaultdict(list)
    for f in files:
        rel = f.relative_to(root).as_posix()
        by_proc[classify(rel)].append(rel)
    # empty process dirs detection
    empty = []
    for d in root.rglob("*"):
        if d.is_dir() and not any(d.iterdir()):
            empty.append(d.relative_to(root).as_posix())
    issues = []   # dicts
    restarts = []
    per_file = {}
    critical_files = []
    # Super technique: GlassFish server.log rotation = AppSvr restart
    for rel in [f.relative_to(root).as_posix() for f in root.rglob("server.log_*.gz")]:
        m = re.search(r'server\.log_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})', rel)
        if m:
            restarts.append({"proc":"appsvr","file":rel,"line":f"[RESTART-ALERT] GlassFish/AppSvr restarted, server.log rotated at {m.group(1).replace('-',':',2) if False else m.group(1)} - check Jedis pool after this time"})
    # Minidump parsing (Linux Breakpad MDMP)
    try:
        import struct as _st, datetime as _dt
        for rel in sorted([f.relative_to(root).as_posix() for f in root.rglob("*.minidump.gz")]):
            pth = root/rel
            if pth.stat().st_size < 10000: continue
            raw = gzip.decompress(pth.read_bytes())
            if raw[:4] != b'MDMP': continue
            sig,ver,nstreams,dir_rva,chk,ts,flags = _st.unpack_from("<4sIIIIIQ", raw, 0)
            streams={}
            for i in range(nstreams):
                st,sz,rva = _st.unpack_from("<III", raw, dir_rva+i*12)
                streams.setdefault(st,[]).append((rva,sz))
            sig_name="UNKNOWN"; crash_thr=""; tcmalloc=""
            if 6 in streams:
                rva,sz = streams[6][0]
                crash_thr = _st.unpack_from("<I", raw, rva)[0]
                code = _st.unpack_from("<I", raw, rva+8)[0]
                sig_name = {11:"SIGSEGV",6:"SIGABRT",15:"SIGTERM",7:"SIGBUS"}.get(code, f"signal {code}")
            ist = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc) + _dt.timedelta(hours=5,minutes=30)
            strs = re.findall(rb'[ -~]{6,}', raw)
            tc = [s.decode() for s in strs if b'tcmalloc' in s or b'invalid pointer' in s]
            if tc: tcmalloc = tc[0][:200]
            issues.append({"proc":classify(rel),"file":rel,"sev":"CRITICAL","type":"MINIDUMP PARSED - "+sig_name,"line":f"crash_thread={crash_thr} time_IST={ist} {tcmalloc}","fix":fix_for("tcmalloc segfault")[1]})
    except Exception as e:
        issues.append({"proc":"backend","file":"minidump_parse","sev":"ERROR","type":"MINIDUMP PARSE","line":str(e),"fix":"Manual minidump review needed"})
    for proc, rels in sorted(by_proc.items()):
        for rel in sorted(rels):
            if not is_logfile(rel):
                if ".minidump" in rel.lower() and (root/rel).stat().st_size > 10000:
                    issues.append({"proc":proc,"file":rel,"sev":"CRITICAL","type":"MINIDUMP/CRASH","line":"minidump file present - worker crashed","fix":fix_for("minidump")[1]})
                    critical_files.append(rel)
                continue
            p = root/rel
            cnt = collections.Counter(); err_samples=[]; total=0
            try:
                for line in iter_lines(p):
                    total+=1
                    # skip binary garbage from double-gz misreads and HTTP access-log / namedValue false positives
                    if sum(1 for ch in line if ord(ch)<9) > 5: continue
                    if re.match(r'^\d+\.\d+\.\d+\.\d+ - - \[', line): continue
                    if "PH_SYS_EVENT_" in line and "named value" in line.lower(): continue
                    sev = severity(line)
                    cnt[sev]+=1
                    if RESTART_RE.search(line) and len(restarts)<MAX_RESTARTS_TOTAL:
                        restarts.append({"proc":proc,"file":rel,"line":line[:400]})
                    for label, pat in CRITICAL_PATTERNS:
                        if pat.search(line):
                            cnt[label]+=1
                            if len(err_samples)<3:
                                err_samples.append((label,line[:350]))
                            break
                    if sev in ("ERROR","CRITICAL","FATAL") and len(err_samples)<5:
                        err_samples.append((sev,line[:350]))
            except Exception as e:
                err_samples.append(("READ_ERROR",str(e)))
            per_file[rel]={"proc":proc,"lines":total,"counts":dict(cnt)}
            # roll up top repeated error messages
            # (kept light: samples above; full norm counted in second pass only for small files? skip for speed)
            for label, sample in err_samples[:2]:
                if label in ("ERROR","CRITICAL","FATAL","MINIDUMP/CRASH","OOM / MEMORY KILLED","DISK FULL","DB/CONNECTION DOWN","SERVICE FAILED","TCMALLOC HEAP CORRUPTION","JEDIS POOL NOT OPEN","GLASSFISH / APPSVR DOWN"):
                    title, fix = fix_for(sample)
                    issues.append({"proc":proc,"file":rel,"sev":"CRITICAL" if label in ("CRITICAL","FATAL","MINIDUMP/CRASH","OOM / MEMORY KILLED","DISK FULL","TCMALLOC HEAP CORRUPTION","JEDIS POOL NOT OPEN","GLASSFISH / APPSVR DOWN") else "ERROR","type":title,"line":sample,"fix":fix})
    # version / status quick facts
    facts={}
    for rel in ["system/AO_VERSION","system/phshowVersion.txt","system/df","system/phstatus","AOLogs/system/AO_VERSION","AOLogs/system/phshowVersion.txt","AOLogs/system/df","AOLogs/system/phstatus"]:
        p=root/rel
        if p.exists():
            try: facts[rel]=p.read_text(errors="replace")[:3000]
            except: pass
    return {"by_proc":{k:sorted(v) for k,v in by_proc.items()},"empty_dirs":empty,"per_file":per_file,"issues":issues,"restarts":restarts,"facts":facts,"total_files":len(files),"redis_validation":validate_redis(root)}

def render_md(name, res):
    out=[]
    out.append(f"# AO Logs Analysis - {name}")
    out.append("")
    out.append("## Inventory by process")
    for proc, files in sorted(res["by_proc"].items()):
        out.append(f"- **{proc}**: {len(files)} files")
        for f in files[:12]: out.append(f"  - {f}")
        if len(files)>12: out.append(f"  - ... +{len(files)-12} more")
    if res["empty_dirs"]:
        out.append("")
        out.append("## [CRITICAL] Collection gaps - empty folders")
        for d in res["empty_dirs"]: out.append(f"- [CRITICAL] EMPTY: {d} - no logs collected for this process in this bundle")
        out.append("- Fix: re-collect AO logs including appsvr + postgres, or confirm this worker role does not run them (pm2 under system/ is the appsvr evidence here).")
    out.append("")
    out.append("## System facts (AO_VERSION / phshowVersion / df / phstatus)")
    out.append("```")
    for k,v in res["facts"].items(): out.append(f"--- {k} ---\n{v[:1500]}")
    out.append("```")
    out.append("")
    out.append("## Redis validation - 6666.conf + redis_info.out + log counts (proof, not assumption)")
    rv = res.get("redis_validation",{})
    if rv:
        out.append("### Config (6666.conf)")
        for k,v in rv.get("conf",{}).items(): out.append(f"- {k}:\n```\n{v[:1200]}\n```")
        for n in rv.get("notes",[]): out.append(f"- NOTE: {n}")
        out.append("### Info snapshot (redis_info.out)")
        for k,v in rv.get("info",{}).items(): out.append(f"- {k}: {v}")
        out.append("### Log counts (full log, not capped sample)")
        for k,v in rv.get("log_counts",{}).items(): out.append(f"- {k}: {v}")
        out.append("- Interpretation: if maxclients is 10000, connected_clients is far below it, and rejected_connections is 0, connection limit is NOT the cause. Look at replica_lost / full_resync / sigterm_shutdown counts instead.")
    out.append("")
    out.append(f"## Restarts / start-stop events - [RESTART-ALERT] ({len(res['restarts'])})")
    out.append("Every line below is a restart/start/stop alert. If it was not planned, treat as a crash and check the CRITICAL section.")
    for r in res["restarts"][:200]:
        out.append(f"- [RESTART-ALERT] [{r['proc']}] {r['file']}: {r['line']}")
    if len(res["restarts"])>200: out.append(f"- ... +{len(res['restarts'])-200} more restart lines (see JSON)")
    out.append("")
    out.append(f"## Issues by process - CRITICAL first ({len(res['issues'])})")
    order={"CRITICAL":0,"ERROR":1}
    for iss in sorted(res["issues"], key=lambda x:(order.get(x["sev"],2), x["proc"])):
        tag="[CRITICAL]" if iss["sev"]=="CRITICAL" else "[ERROR]"
        out.append(f"- {tag} [{iss['proc']}] {iss['type']} - {iss['file']}")
        out.append(f"  Evidence: {iss['line']}")
        out.append(f"  Fix: {iss['fix']}")
    out.append("")
    out.append("## Per-file line/severity counts")
    for f,info in sorted(res["per_file"].items()):
        out.append(f"- {f} ({info['proc']}): {info['lines']} lines {info['counts']}")
    out.append("")
    out.append("Generated locally by analyze_ao.py - FortiSIEM AO logs, local only.")
    return "\n".join(out)

def main():
    args=sys.argv[1:]
    if not args: print(__doc__); return
    src=Path(args[0])
    outdir=Path("analysis")/ (src.stem if src.is_file() else src.name)
    if "--out" in args: outdir=Path(args[args.index("--out")+1])
    if "--name" in args: label=args[args.index("--name")+1]
    else: label=src.name
    print(f"Extracting {src} -> {outdir}")
    root=extract_archive(src, outdir/"extracted")
    print("Analyzing...")
    res=analyze(root)
    md=render_md(label,res)
    (outdir/"AO_ANALYSIS_REPORT.md").write_text(md,encoding="utf-8")
    (outdir/"AO_ANALYSIS_REPORT.txt").write_text(md,encoding="utf-8")
    (outdir/"AO_ANALYSIS_REPORT.json").write_text(json.dumps(res,indent=2,default=str),encoding="utf-8")
    crit=sum(1 for i in res["issues"] if i["sev"]=="CRITICAL")
    print(f"Files: {res['total_files']}  Issues: {len(res['issues'])} (CRITICAL {crit})  Restarts: {len(res['restarts'])}")
    print(f"Report: {outdir/'AO_ANALYSIS_REPORT.md'}")
    print("First CRITICAL/restart lines:")
    for i in res["issues"][:10]: print(" ",i["sev"],i["proc"],i["type"],i["line"][:160])
    for r in res["restarts"][:10]: print("  [RESTART-ALERT]",r["proc"],r["line"][:160])

if __name__=="__main__": main()
