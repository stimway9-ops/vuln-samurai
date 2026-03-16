# VulnSamurai ⚔

Web application penetration testing tool.
Scan engines: whatweb, nikto, gobuster, wapiti, sqlmap, nuclei.

## Requirements

- Docker installed and running
  - Linux:   https://docs.docker.com/engine/install/
  - Windows: https://docs.docker.com/desktop/install/windows/
  - macOS:   https://docs.docker.com/desktop/install/mac/

---

## Run — Linux / macOS

```bash
chmod +x run.sh && ./run.sh
```

## Run — Windows PowerShell (recommended)

Right-click `run.ps1` → Run with PowerShell

Or from a PowerShell terminal:
```powershell
.\run.ps1
```

## Run — Windows CMD (double-click)

Double-click `run.bat`

---

First run builds the image (~15 min, downloads all scan tools).
Every run after that starts in seconds.

Open: http://localhost:3000

---

## Daily use (all platforms)

```bash
docker start vulnsamurai    # start
docker stop vulnsamurai     # stop
docker logs -f vulnsamurai  # live logs
```

## Per-service logs

```bash
docker exec vulnsamurai tail -f /data/log/backend.log
docker exec vulnsamurai tail -f /data/log/frontend.log
docker exec vulnsamurai tail -f /data/log/mongod.log
```

## Rebuild after code changes

Linux/macOS:  ./run.sh
Windows:      .\run.ps1
