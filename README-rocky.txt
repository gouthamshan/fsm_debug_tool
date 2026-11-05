FortiSIEM Log Terminal - Rocky Linux version
==============================================
Separate from the Windows version. Same app, Linux launcher, no Windows paths.

DROP-FOLDER MODE - NO BROWSER NEEDED (recommended for Rocky investigations)
  This is the way to use it on Rocky without opening a browser.
  Put all AO logs for one investigation in a path, run one command, get a report.

  mkdir -p input/my-incident
  cp /path/to/worker1_AOlogs.tar /path/to/SuperAOlogs.tar input/my-incident/
  ./scan.sh my-incident

  Or put tars straight in input/ and run:
  ./scan.sh

  Watch mode - auto-scans new tars every 30 seconds, no browser:
  ./scan.sh --watch
  Drop a new .tar into input/ at any time, it will be analyzed automatically.

  What happens:
    - Each .tar/.tgz/.tar.gz/.zip in input/ is untarred safely (colon-safe names)
    - backend / appsvr (pm2 + GlassFish) / system / postgres classified
    - Redis validated: 6666.conf + redis_info.out + log counts (proof, not assumption)
    - Minidumps parsed: signal, crash thread, IST time, tcmalloc invalid free
    - Detects: Jedis pool not open, lookup table cannot load, FortiGuard 87MB load,
      shared buffer drops, GlassFish restarts via server.log rotation,
      phRuleWorker blocking, segfaults, disk/memory pressure
    - Every restart tagged [RESTART-ALERT], CRITICAL labeled first, fix per issue
  Reports:
    reports/<bundle>_AO_ANALYSIS_REPORT.md   - full report per bundle
    reports/SUMMARY.md                       - combined summary across all bundles
    analysis/<bundle>/AO_ANALYSIS_REPORT.json - machine-readable, for scripts

  Input folder is:  <this folder>/input/
  You can also do one investigation per subfolder: input/<name>/, then ./scan.sh <name>

START (Rocky Linux, graphical or SSH) - browser mode, optional
  chmod +x start-terminal.sh
  ./start-terminal.sh
  Then open: http://127.0.0.1:8765
  If you are on SSH / headless, the terminal will print the URL - open it
  via SSH tunnel: ssh -L 8765:127.0.0.1:8765 <rocky-host>

PYTHON - no manual install needed in most cases
  Rocky Linux ships python3 (usually 3.9+). This app uses Python stdlib only:
  http.server, gzip, tarfile, zipfile, json, re, pathlib, base64, struct.
  No pip, no venv, no packages to install.
  start-terminal.sh auto-detects python3 / /usr/bin/python3 / python,
  checks it actually runs, and if missing tries: sudo dnf install -y python3
  If dnf needs your sudo password, type it - that is the only manual step.
  Check yourself: python3 --version  (needs 3.8 or newer)

CLI MODE (no browser)
  python3 app.py --cli <logfile>
  python3 app.py --stats <logfile>
  python3 analyze_ao.py <AO-logs.tar> --out analysis/<name> --name <name>
  python3 parse_minidump.py <minidump.gz> [...]

UPLOAD
  Drag & drop .log .txt .csv .gz .zip .tar .tgz into the web terminal.
  AO .tar bundles auto-extract and analyze backend/appsvr/system,
  tag restarts [RESTART-ALERT], label CRITICAL, list fixes,
  validate Redis (6666.conf + redis_info.out), parse minidumps,
  detect FortiGuard load, lookup failures, and shared-buffer drops.
  Report is saved to uploads/<timestamp>AO_ANALYSIS_REPORT.md

PRIVACY
  Binds to 127.0.0.1 only. Uploads stay in ./uploads on this machine.
  Nothing is sent to the cloud. Delete uploads/ and analysis/ when done.

FILES IN THIS FOLDER
  app.py                - web + CLI terminal
  analyze_ao.py         - AO tar analyzer (backend/appsvr/system, Redis validation, minidumps)
  parse_minidump.py     - standalone minidump reader (signal, thread, tcmalloc)
  start-terminal.sh     - Rocky launcher (this file)
  start-terminal.bat    - Windows launcher (kept, ignore on Linux)
  fortisiem-sample.log  - sample to test
  analysis/             - previous reports (Worker, Super, Redis proof, rule/FortiGuard)
  uploads/              - your uploads will land here

TROUBLESHOOTING
  - "python3 not found": sudo dnf install -y python3, then ./start-terminal.sh again
  - Port busy: another instance is running on 8765. Stop it (Ctrl+C in its window),
    or run: python3 app.py --port 8766
  - Permission denied on .sh: chmod +x start-terminal.sh
  - Works on any Rocky 8/9, AlmaLinux, CentOS Stream - it is just bash + python3.
