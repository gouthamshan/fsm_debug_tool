# FortiSIEM AO Log Terminal

Local-only log triage tool for FortiSIEM AO (AccelOps) log bundles.
Upload or drop `.tar` AO logs, it untars them, classifies backend / appsvr / system,
validates Redis, parses minidumps, and writes a CRITICAL-first report with
[RESTART-ALERT] tags and a fix per issue. No browser required for investigations.

> Privacy: binds to 127.0.0.1 only, files stay in `uploads/` / `input/` on your PC.
> Never commit real AO logs, configs, or reports with customer data to Git.

## Quick start - drop-folder (no browser, recommended)

```bash
# Rocky Linux / Linux
chmod +x scan.sh start-terminal.sh
mkdir -p input/my-incident
cp /path/to/worker1_AOlogs.tar /path/to/SuperAOlogs.tar input/my-incident/
./scan.sh my-incident

# Watch mode: auto-scan new tars every 30s
./scan.sh --watch
```

Reports: `reports/<bundle>_AO_ANALYSIS_REPORT.md`, combined `reports/SUMMARY.md`.

## Quick start - browser (optional)

Windows:
```bat
start-terminal.bat
```
This auto-detects real `python3.exe` (skips the Microsoft Store shim), and if
none is found tries `winget install -e --id Python.Python.3.12`.

Linux / Rocky:
```bash
chmod +x start-terminal.sh
./start-terminal.sh
# open http://127.0.0.1:8765
```
If `python3` is missing it tries `sudo dnf install -y python3`.

## CLI

```bash
python3 app.py --cli <logfile>          # interactive troubleshooting terminal
python3 app.py --stats <logfile>        # one-shot stats
python3 analyze_ao.py <AO-logs.tar> --out analysis/<name> --name <name>
python3 parse_minidump.py <minidump.gz> [...]
python3 scan_all.py [investigation-name]  # drop-folder scanner, no browser
```

## What it detects

- Backend / appsvr (pm2 Node + GlassFish) / system / postgres classification
- Redis validation: `6666.conf` + `redis_info.out` + log counts (maxclients proof, replication, full resync loop, SIGTERM restarts) - see `analysis/REDIS_PROOF.md` in the full local copy for the method
- Minidumps (Linux Breakpad MDMP): signal, crash thread, IST time, tcmalloc invalid free / SIGSEGV at 0x0
- Jedis pool not open, lookup table cannot load, FortiGuard feed load (~87 MB per cycle), shared buffer drops
- GlassFish restarts via `server.log` rotation, pm2 restarts, phMonitor starting all modules
- Every restart tagged `[RESTART-ALERT]`, CRITICAL labeled first, fix per issue

## Requirements

- Python 3.8+ (Rocky ships it, Windows via winget/python.org)
- Stdlib only: `http.server, gzip, tarfile, zipfile, json, re, pathlib, base64, struct`
- No pip, no venv, no build step

## Repository layout

```
app.py                  # web (127.0.0.1:8765) + CLI terminal
analyze_ao.py           # AO tar analyzer
scan_all.py / scan.sh   # drop-folder scanner (input/ -> reports/)
parse_minidump.py       # standalone minidump reader
start-terminal.bat      # Windows launcher (auto-installs Python via winget if needed)
start-terminal.sh       # Linux/Rocky launcher (auto-installs python3 via dnf if needed)
fortisiem-sample.log    # synthetic sample (TEST-NET IPs, no real data)
input/ reports/ uploads/  # your data goes here - gitignored, never commit
```

## Security - before you publish or share

This tool processes sensitive logs. The repo itself contains no real logs, but:
- Never commit `input/`, `uploads/`, `reports/`, `analysis/**/AOLogs`, `*.tar`, `*.log.gz`
- `6666.conf` contains a Redis `requirepass`, `phoenix_config` contains secrets,
  AO reports contain hostnames, IPs, and license serials - all gitignored here.
- If you fork this, run `git log -p` and grep for passwords before pushing.
- The sample log uses documentation IPs (203.0.113.x, 10.0.0.x) only.

## License

MIT - see LICENSE. Use at your own risk, test on a lab node first.
FortiSIEM, FortiGuard, and related marks belong to Fortinet. This is an
independent community tool, not affiliated with Fortinet.
