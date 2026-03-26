"""
VulnSamurai Scan Engine
Runs tools sequentially: whatweb → nikto → gobuster → wapiti → sqlmap → nuclei
Each tool writes parsed results incrementally to MongoDB.
"""

from __future__ import annotations
import asyncio
import json
import re
import subprocess
from datetime import datetime, timezone
from typing import List, Optional, AsyncGenerator, Tuple, Tuple

from bson import ObjectId

from database import scans_col
from models import VulnDoc, PayloadDoc, ScanSummary, Severity

# ── Engine order & weights (must sum to 100) ───────────────

ENGINES = [
    ("whatweb",  10),
    ("nikto",    20),
    ("gobuster", 15),
    ("wapiti",   20),
    ("sqlmap",   20),
    ("nuclei",   15),
]

# ── Severity helpers ───────────────────────────────────────

def _sev(s: str) -> Severity:
    s = s.lower()
    if s in ("high", "critical"): return Severity.high
    if s in ("medium", "moderate"): return Severity.medium
    if s in ("low",): return Severity.low
    return Severity.info

# ── Subprocess runner (async) ──────────────────────────────

async def _run(cmd: List[str], timeout: int = 300) -> Tuple[str, str, int]:
    """Run a subprocess asynchronously, return (stdout, stderr, returncode)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return "", "TIMEOUT", -1

# ── Per-engine parsers ─────────────────────────────────────

def _parse_whatweb(stdout: str, url: str) -> tuple[List[VulnDoc], List[PayloadDoc]]:
    vulns, payloads = [], []
    # WhatWeb outputs one line per URL: URL [200 OK] Server[Apache], ...
    for line in stdout.splitlines():
        if not line.strip():
            continue
        # Extract interesting fields
        findings = re.findall(r'(\w[\w\s\-]+)\[([^\]]+)\]', line)
        for name, value in findings:
            name = name.strip()
            if name.lower() in ("http", "https", "200", "301", "302"):
                continue
            vulns.append(VulnDoc(
                name=f"Technology detected: {name}",
                severity=Severity.info,
                recommendation=f"Detected {name} version {value}. Keep software up to date.",
                engine="whatweb",
                raw=f"{name}: {value}",
            ))
    return vulns, payloads


def _parse_nikto(stdout: str, url: str) -> tuple[List[VulnDoc], List[PayloadDoc]]:
    vulns, payloads = [], []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("+"):
            continue
        # Skip informational header lines
        if any(x in line for x in ("Target IP:", "Target Hostname:", "Target Port:",
                                    "Start Time:", "End Time:", "Nikto", "requests:")):
            continue
        # Severity heuristic
        sev = Severity.info
        if any(w in line.lower() for w in ("sql", "injection", "xss", "rce", "exec",
                                            "remote", "shell", "traversal", "overflow")):
            sev = Severity.high
        elif any(w in line.lower() for w in ("csrf", "auth", "password", "bypass",
                                              "sensitive", "disclosure")):
            sev = Severity.medium
        elif any(w in line.lower() for w in ("cookie", "header", "version", "outdated")):
            sev = Severity.low

        clean = line.lstrip("+ ").strip()
        vulns.append(VulnDoc(
            name=clean[:80],
            severity=sev,
            recommendation="Review the flagged item and apply the relevant security patch or configuration fix.",
            engine="nikto",
            raw=clean,
        ))
        if sev in (Severity.high, Severity.medium):
            payloads.append(PayloadDoc(
                vulnerability=clean[:60],
                payload=url,
                result="Detected by Nikto",
                result_severity=sev,
                description=clean,
                engine="nikto",
            ))
    return vulns, payloads


def _parse_gobuster(stdout: str, url: str) -> tuple[List[VulnDoc], List[PayloadDoc]]:
    vulns, payloads = [], []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("/usr"):
            continue
        # Lines look like: /admin                (Status: 200) [Size: 1234]
        m = re.match(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
        if not m:
            continue
        path, status = m.group(1), m.group(2)
        sev = Severity.info
        sensitive = ("/admin", "/backup", "/config", "/.git", "/wp-admin",
                     "/phpmyadmin", "/.env", "/api", "/debug")
        if any(path.startswith(s) for s in sensitive):
            sev = Severity.medium
        if status in ("200", "301", "302"):
            vulns.append(VulnDoc(
                name=f"Exposed path: {path} (HTTP {status})",
                severity=sev,
                recommendation=f"Restrict access to {path} if it should not be public.",
                engine="gobuster",
                raw=line,
            ))
    return vulns, payloads


def _parse_wapiti(stdout: str, url: str) -> tuple[List[VulnDoc], List[PayloadDoc]]:
    vulns, payloads = [], []
    # Wapiti can output JSON with -f json
    try:
        data = json.loads(stdout)
        for vuln_type, entries in data.get("vulnerabilities", {}).items():
            for entry in entries:
                sev_str = entry.get("level", "Low")
                sev = _sev(sev_str)
                info = entry.get("info", "")
                curl = entry.get("curl_command", "")
                param = entry.get("parameter", "")
                vulns.append(VulnDoc(
                    name=f"{vuln_type}: {info[:60]}",
                    severity=sev,
                    recommendation=f"Sanitise input for parameter '{param}'.",
                    engine="wapiti",
                    raw=info,
                ))
                if curl:
                    payloads.append(PayloadDoc(
                        vulnerability=vuln_type,
                        payload=curl[:120],
                        result="Triggered by Wapiti",
                        result_severity=sev,
                        description=info,
                        engine="wapiti",
                    ))
    except json.JSONDecodeError:
        # Fallback: parse plain-text output
        for line in stdout.splitlines():
            if "Found vulnerability" in line or "Vulnerability" in line:
                vulns.append(VulnDoc(
                    name=line.strip()[:100],
                    severity=Severity.medium,
                    recommendation="Review Wapiti findings.",
                    engine="wapiti",
                    raw=line.strip(),
                ))
    return vulns, payloads


def _parse_sqlmap(stdout: str, url: str) -> tuple[List[VulnDoc], List[PayloadDoc]]:
    vulns, payloads = [], []
    injectable_params = re.findall(r'Parameter:\s+(.+?)\s+\((.+?)\)', stdout)
    payloads_found    = re.findall(r'Payload:\s+(.+)', stdout)
    technique_map     = {
        "boolean-based": "SQL Injection (Boolean-based)",
        "time-based":    "SQL Injection (Time-based)",
        "error-based":   "SQL Injection (Error-based)",
        "union query":   "SQL Injection (UNION-based)",
        "stacked":       "SQL Injection (Stacked queries)",
    }
    if injectable_params:
        for param, technique in injectable_params:
            vuln_name = technique_map.get(technique.lower(), "SQL Injection")
            vulns.append(VulnDoc(
                name=vuln_name,
                severity=Severity.high,
                recommendation=(
                    f"Parameter '{param.strip()}' is injectable. "
                    "Use parameterised queries / prepared statements immediately."
                ),
                engine="sqlmap",
                raw=f"{param} via {technique}",
            ))
        for p in payloads_found[:5]:  # cap at 5 payloads
            payloads.append(PayloadDoc(
                vulnerability="SQL Injection",
                payload=p.strip()[:120],
                result="Injection confirmed",
                result_severity=Severity.high,
                description="SQLMap confirmed injectable parameter.",
                engine="sqlmap",
            ))
    elif "not injectable" not in stdout.lower() and "sqlmap identified" in stdout.lower():
        vulns.append(VulnDoc(
            name="Potential SQL Injection",
            severity=Severity.medium,
            recommendation="Manual review recommended. SQLMap found suspicious patterns.",
            engine="sqlmap",
            raw="SQLMap partial detection",
        ))
    return vulns, payloads


def _parse_nuclei(stdout: str, url: str) -> tuple[List[VulnDoc], List[PayloadDoc]]:
    vulns, payloads = [], []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Nuclei JSON output (-json flag)
        try:
            obj = json.loads(line)
            sev   = _sev(obj.get("info", {}).get("severity", "info"))
            name  = obj.get("info", {}).get("name", "Unknown")
            desc  = obj.get("info", {}).get("description", "")
            matched = obj.get("matched-at", url)
            template = obj.get("template-id", "")
            vulns.append(VulnDoc(
                name=name,
                severity=sev,
                recommendation=desc or f"Review template: {template}",
                engine="nuclei",
                raw=json.dumps(obj),
            ))
            if sev in (Severity.high, Severity.medium):
                payloads.append(PayloadDoc(
                    vulnerability=name,
                    payload=matched[:120],
                    result=f"Nuclei: {template}",
                    result_severity=sev,
                    description=desc[:200],
                    engine="nuclei",
                ))
        except json.JSONDecodeError:
            # Plain text fallback
            if "[" in line and "]" in line:
                vulns.append(VulnDoc(
                    name=line[:100],
                    severity=Severity.info,
                    recommendation="Review Nuclei finding.",
                    engine="nuclei",
                    raw=line,
                ))
    return vulns, payloads

# ── Summary builder ────────────────────────────────────────

def _build_summary(vulns: List[VulnDoc]) -> ScanSummary:
    s = ScanSummary()
    for v in vulns:
        if v.severity == Severity.high:   s.high   += 1
        elif v.severity == Severity.medium: s.medium += 1
        elif v.severity == Severity.low:   s.low    += 1
        else:                              s.info   += 1
    s.total = len(vulns)
    return s

# ── Engine command builders ────────────────────────────────

def _commands(url: str) -> dict:
    return {
        "whatweb": [
            "whatweb", "-a", "3", "--no-errors", url
        ],
        "nikto": [
            "nikto", "-h", url, "-nointeractive", "-ask", "no",
            "-Plugins", "headers,shellshock,xss,sqli,traversal"
        ],
        "gobuster": [
            "gobuster", "dir",
            "-u", url,
            "-w", "/usr/share/wordlists/common.txt",
            "-t", "10",
            "--no-error",
            "-q",
        ],
        "wapiti": [
            "wapiti", "-u", url,
            "-f", "json",
            "-o", "/tmp/wapiti_out.json",
            "--flush-attacks",
            "--scope", "page",
            "-m", "xss,sql,xxe,csrf,ssrf,blindsql,exec",
        ],
        "sqlmap": [
            "sqlmap", "-u", url,
            "--batch",
            "--level", "2",
            "--risk", "1",
            "--output-dir", "/tmp/sqlmap_out",
            "--forms",
            "--crawl", "2",
        ],
        "nuclei": [
            "nuclei", "-u", url,
            "-json",
            "-silent",
            "-severity", "low,medium,high,critical",
            "-timeout", "10",
        ],
    }

PARSERS = {
    "whatweb":  _parse_whatweb,
    "nikto":    _parse_nikto,
    "gobuster": _parse_gobuster,
    "wapiti":   _parse_wapiti,
    "sqlmap":   _parse_sqlmap,
    "nuclei":   _parse_nuclei,
}

TIMEOUTS = {
    "whatweb":  60,
    "nikto":    180,
    "gobuster": 120,
    "wapiti":   240,
    "sqlmap":   300,
    "nuclei":   180,
}

# ── Wapiti special: reads from output file ────────────────

async def _run_wapiti(url: str) -> str:
    import os
    out_file = "/tmp/wapiti_out.json"
    cmd = _commands(url)["wapiti"]
    await _run(cmd, timeout=TIMEOUTS["wapiti"])
    if os.path.exists(out_file):
        with open(out_file) as f:
            return f.read()
    return ""

# ── Main scan runner ───────────────────────────────────────

async def run_scan(scan_id: str, url: str):
    """
    Entry point called from FastAPI background task.
    Runs each engine sequentially, writes progress to MongoDB after each.
    """
    col = scans_col()
    object_id = ObjectId(scan_id)
    all_vulns: List[VulnDoc]    = []
    all_payloads: List[PayloadDoc] = []

    await col.update_one(
        {"_id": object_id},
        {"$set": {"status": "running", "started_at": datetime.now(timezone.utc), "progress": 0}}
    )

    progress_cursor = 0

    for engine_name, weight in ENGINES:
        # Update current engine in DB
        await col.update_one(
            {"_id": object_id},
            {"$set": {"current_engine": engine_name, "progress": progress_cursor}}
        )

        try:
            if engine_name == "wapiti":
                stdout = await _run_wapiti(url)
                stderr, rc = "", 0
            else:
                cmd = _commands(url)[engine_name]
                stdout, stderr, rc = await _run(cmd, timeout=TIMEOUTS[engine_name])

            parser  = PARSERS[engine_name]
            vulns, payloads = parser(stdout, url)

        except Exception as exc:
            print(f"[SCAN] Engine {engine_name} error: {exc}")
            vulns, payloads = [], []

        all_vulns.extend(vulns)
        all_payloads.extend(payloads)
        progress_cursor += weight

        # Incremental write — results visible in real time
        summary = _build_summary(all_vulns)
        await col.update_one(
            {"_id": object_id},
            {"$set": {
                "vulnerabilities": [v.model_dump() for v in all_vulns],
                "payloads":        [p.model_dump() for p in all_payloads],
                "summary":         summary.model_dump(),
                "progress":        progress_cursor,
            }}
        )

    # Final update
    await col.update_one(
        {"_id": object_id},
        {"$set": {
            "status":       "done",
            "finished_at":  datetime.now(timezone.utc),
            "progress":     100,
            "current_engine": None,
        }}
    )
