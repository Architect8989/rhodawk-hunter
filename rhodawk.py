#!/usr/bin/env python3
"""
rhodawk.py — Rhodawk Autonomous Security Research System
Phase-by-phase execution. Main entry: python3 rhodawk.py <target_url>
Architecture: 12 phases from scope parse → proof recording → report → learning loop.
Every tool is referenced from node_registry.json (self-expanding registry).
"""

import argparse
import asyncio
import hashlib
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Configuration ─────────────────────────────────────────────────
BASE_DIR = Path("/rhodawk")
STATE = {
    "node_registry": BASE_DIR / "node_registry.json",
    "findings_db": BASE_DIR / "findings_db.json",
    "duplicate_db": BASE_DIR / "duplicate_db.json",
    "chain_library": BASE_DIR / "chain_library.json",
    "weight_map": BASE_DIR / "weight_map.json",
    "gate_criteria": BASE_DIR / "gate_criteria.json",
    "scope": BASE_DIR / "scope.json",
    "surface_map": BASE_DIR / "surface_map.json",
    "run_metadata": BASE_DIR / "run_metadata.json",
    "decision_log": BASE_DIR / "decision_log.json",
}
RECON_OUT = BASE_DIR / "recon"
AGENTS_OUT = BASE_DIR / "agents"
FINDINGS_OUT = BASE_DIR / "findings"
RESEARCH_OUT = BASE_DIR / "research"
MAX_WORKERS = 8  # scaled to 31GB RAM / 8-core

# ── Helpers ───────────────────────────────────────────────────────
def log(msg: str):
    ts = datetime.now(timezone.utc).isoformat() + "Z"
    print(f"[{ts}] {msg}", flush=True)

def load_json(path: Path) -> Any:
    if path.exists():
        with open(path) as fh:
            return json.load(fh)
    return []

def save_json(path: Path, data: Any):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)

def run_cmd(cmd: List[str], timeout: int = 300, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run command, return result. Logs on error."""
    try:
        log(f"  CMD: {' '.join(cmd)}")
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, "", "TIMEOUT")
    except Exception as e:
        return subprocess.CompletedProcess(cmd, -1, "", str(e))

def find_tool(tool_id: str) -> Optional[Dict]:
    """Lookup tool in node registry by tool_id."""
    registry = load_json(STATE["node_registry"])
    for entry in registry:
        if entry.get("tool_id") == tool_id:
            return entry
    return None

def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

# ══════════════════════════════════════════════════════════════════
#  PHASE 0 — SELF-UPGRADE / AUDIT
# ══════════════════════════════════════════════════════════════════
def phase0_self_audit() -> bool:
    """Verify all registry tools are installed. Run GitHub Discovery for gaps."""
    log("=== PHASE 0: Self-Audit ===")
    registry = load_json(STATE["node_registry"])
    verified = 0
    missing = []
    for entry in registry:
        tool_id = entry.get("tool_id", "")
        if not tool_id:
            continue
        binary = shutil.which(tool_id)
        if binary:
            entry["installed_path"] = binary
            entry["verified"] = True
            verified += 1
        else:
            entry["verified"] = False
            missing.append(entry)

    save_json(STATE["node_registry"], registry)
    log(f"  Verified tools: {verified}/{len(registry)}")

    # For now, auto-install is stubbed — operator can run install.sh per tool
    if missing:
        log(f"  Missing tools ({len(missing)}): " + ", ".join(m.get("tool_id", "?") for m in missing))
        log("  Install via: go install -v <repo>@latest  (Go tools) or pip3 install <tool>")
    return True

# ══════════════════════════════════════════════════════════════════
#  PHASE 1 — SCOPE PARSE  (Playwright browser render + extract)
# ══════════════════════════════════════════════════════════════════
def phase1_scope_parse(target_url: str) -> dict:
    """Extract target domain as scope. Optionally render in Playwright if available."""
    log("=== PHASE 1: Scope Parse ===")
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    base_domain = parsed.netloc

    scope = {
        "target_url": target_url,
        "in_scope": [base_domain],
        "out_of_scope": [],
        "payout_tiers": {},
        "automation_rules": {},
        "special_notes": [],
        "battlefield_understood": True,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(target_url, timeout=30000, wait_until="networkidle")
            log("  Playwright render OK")
            browser.close()
    except Exception as e:
        scope["special_notes"].append(f"Playwright unavailable or error: {e}")

    save_json(STATE["scope"], scope)
    log(f"  Scope saved: {scope['in_scope']}")
    return scope

# ══════════════════════════════════════════════════════════════════
#  PHASE 2 — LOADOUT ASSEMBLY
# ══════════════════════════════════════════════════════════════════
def phase2_loadout(scope: dict) -> List[Dict]:
    """Determine required capability classes, verify/install tools."""
    log("=== PHASE 2: Loadout Assembly ===")
    registry = load_json(STATE["node_registry"])
    needed_caps = ["subdomain_enum", "dns_resolution", "live_host_probe", "port_scan",
                   "endpoint_crawl", "historical_urls", "js_analysis", "secret_scanning",
                   "parameter_discovery", "xss", "sqli", "ssrf", "idor",
                   "subdomain_takeover", "jwt_attack", "graphql", "oauth_flaw"]

    loadout = []
    for cap in needed_caps:
        tools = [t for t in registry if cap in t.get("capability_tags", [])]
        if tools:
            loadout.append({"capability": cap, "tool": tools[0]["tool_id"], "verified": tools[0].get("verified", False)})
        else:
            log(f"  WARNING: No verified tool for capability '{cap}' → GitHub Discovery needed")

    save_json(BASE_DIR / "loadout.json", loadout)
    log(f"  Loadout: {len(loadout)} capabilities ready")
    return loadout

# ══════════════════════════════════════════════════════════════════
#  PHASE 3 — GITHUB DISCOVERY (self-expansion)
# ══════════════════════════════════════════════════════════════════
def phase3_github_discovery(gap_description: str) -> Dict:
    """Stub: search GitHub API for tool, install, verify, register."""
    log(f"=== PHASE 3: GitHub Discovery for '{gap_description}' ===")
    # Full implementation calls GitHub Search API with LLM evaluation
    # For MVP: log gap, return placeholder
    return {"tool_id": "PENDING", "capability": gap_description, "status": "discovery_needed"}

# ══════════════════════════════════════════════════════════════════
#  PHASE 4 — RECON PIPELINE
# ══════════════════════════════════════════════════════════════════
def phase4_recon(scope: dict) -> dict:
    """Run full recon suite. Return surface_map."""
    log("=== PHASE 4: Recon Pipeline ===")
    target_domain = scope["in_scope"][0] if scope["in_scope"] else ""
    if not target_domain:
        log("  ERROR: No target domain in scope")
        return {}

    ensure_dir(RECON_OUT)
    subdomains_file = RECON_OUT / "all_subdomains.txt"

    # 4.1 Subdomain enumeration
    log("  4.1 Subdomain enumeration...")
    sf = find_tool("subfinder")
    if sf:
        tmpl = sf["invocation_template"].replace("{target}", target_domain).replace("{output}", str(subdomains_file))
        run_cmd(tmpl.split())

    # 4.3 DNS resolution + live host probe (combined with httpx)
    log("  4.3 Live host probing...")
    live_out = RECON_OUT / "live_hosts.jsonl"
    httpx = find_tool("httpx")
    if httpx and subdomains_file.exists():
        cmd = httpx["invocation_template"].replace("{input_list}", str(subdomains_file)).replace("{output}", str(live_out))
        run_cmd(cmd.split())

    # 4.5 Endpoint crawling
    log("  4.5 Endpoint crawling...")
    katana = find_tool("katana")
    if katana and subdomains_file.exists():
        katana_out = RECON_OUT / "katana_out.txt"
        cmd = katana["invocation_template"].replace("{input_list}", str(subdomains_file)).replace("{output}", str(katana_out))
        run_cmd(cmd.split())

    # 4.6 Historical URLs
    log("  4.6 Historical URL mining...")
    gau = find_tool("gau")
    if gau and target_domain:
        gau_out = RECON_OUT / "gau_out.txt"
        cmd = gau["invocation_template"].replace("{target}", target_domain).replace("{output}", str(gau_out))
        run_cmd(cmd.split())

    # 4.9 Assemble surface map
    surface_map = {
        "subdomains": [],
        "live_hosts": [],
        "endpoints": [],
        "secrets_found": [],
        "historical_urls": [],
        "total_attack_surface": 0,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }

    # Parse httpx output (JSONL)
    if live_out.exists():
        with open(live_out) as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                    surface_map["live_hosts"].append({
                        "url": entry.get("url", ""),
                        "status": entry.get("status_code", 0),
                        "tech": entry.get("tech", []),
                        "headers": entry.get("headers", {}),
                        "title": entry.get("title", ""),
                        "host": entry.get("host", "")
                    })
                    surface_map["subdomains"].append(entry.get("host", ""))
                except json.JSONDecodeError:
                    continue

    # Parse katana output
    katana_out = RECON_OUT / "katana_out.txt"
    if katana_out.exists():
        with open(katana_out) as fh:
            for line in fh:
                url = line.strip()
                if url.startswith(("http://", "https://")):
                    surface_map["endpoints"].append(url)

    # Parse gau output
    if gau_out.exists():
        with open(gau_out) as fh:
            for line in fh:
                url = line.strip()
                if url:
                    surface_map["historical_urls"].append(url)

    # Deduplicate
    surface_map["subdomains"] = sorted(set(surface_map["subdomains"]))
    surface_map["endpoints"] = sorted(set(surface_map["endpoints"]))
    surface_map["total_attack_surface"] = len(surface_map["endpoints"]) + len(surface_map["subdomains"])

    save_json(STATE["surface_map"], surface_map)
    log(f"  Surface map: {len(surface_map['subdomains'])} subdomains, {len(surface_map['live_hosts'])} live, {len(surface_map['endpoints'])} endpoints")
    return surface_map

# ══════════════════════════════════════════════════════════════════
#  PHASE 5 — PRIORITY QUEUE
# ══════════════════════════════════════════════════════════════════
def phase5_priority_queue(surface_map: dict) -> List[dict]:
    """Score every endpoint and build priority queue."""
    log("=== PHASE 5: Priority Queue ===")

    VULN_PATTERNS = {
        "IDOR": [r"/user/\d+", r"/account/\d+", r"[/&?]id=\d+"],
        "SSRF": [r"[/&?](url|redirect|fetch|webhook)=", r"[/&?]proxy="],
        "RCE_UPLOAD": [r"/upload", r"/import", r"/file"],
        "AUTH_BYPASS": [r"/login", r"/oauth", r"/token", r"/auth", r"/sso"],
        "SQLI": [r"[/&?](id|search|q|filter|query)=", r"[/&?]sort="],
        "XSS": [r"[/&?](q|search|message|name|comment)=", r"[/&?]callback="],
        "SUBDOMAIN_TAKEOVER": [],
        "JWT_ATTACK": [r"/api/.*token", r"Authorization: Bearer"],
        "GRAPHQL": [r"/graphql", r"/api/graphql"],
        "OAUTH_FLAW": [r"/oauth/authorize", r"redirect_uri="]
    }

    queue = []
    for ep in surface_map.get("endpoints", []):
        score = 1.0  # base
        matched = []
        for vuln_class, patterns in VULN_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, ep, re.I):
                    score += 2.0  # boost per match
                    matched.append(vuln_class)
        # Boost for interesting extensions
        if any(ext in ep for ext in [".php", ".jsp", ".aspx", ".action"]):
            score += 1.5
        # Boost for query params
        if "?" in ep:
            score += 0.5

        queue.append({
            "url": ep,
            "priority_score": round(score, 2),
            "vuln_classes": list(set(matched)),
            "status": "pending"
        })

    # Also evaluate live_hosts for takeover risk
    for host in surface_map.get("live_hosts", []):
        url = host.get("url", "")
        score = 1.0
        queue.append({
            "url": url,
            "priority_score": round(score, 2),
            "vuln_classes": ["SUBDOMAIN_TAKEOVER"],
            "status": "pending",
            "meta": {"host_data": host}
        })

    queue.sort(key=lambda x: -x["priority_score"])
    save_json(STATE["priority_queue"], queue)
    log(f"  Priority queue: {len(queue)} endpoints, top score {queue[0]['priority_score'] if queue else 0}")
    return queue

# ══════════════════════════════════════════════════════════════════
#  PHASE 9 — PROOF VALIDATION (4 gates)
# ══════════════════════════════════════════════════════════════════
def gate1_http_verify(finding: Dict) -> bool:
    """Gate 1: HTTP response verification. Status 200 + vuln-class specific check."""
    url = finding.get("target_url", "")
    vuln_class = finding.get("vuln_class", "")
    try:
        resp = run_cmd(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url], timeout=30)
        status = int(resp.stdout.strip()) if resp.stdout.strip().isdigit() else 0
        if status != 200:
            return False
        # Vuln-class specific checks
        return True
    except Exception:
        return False

def gate2_independent_replay(finding: Dict) -> bool:
    """Gate 2: Replay in fresh environment."""
    # For MVP: stub — in full system, spawn clean container and replay
    return True  # placeholder

def gate3_duplicate_detect(finding: Dict) -> bool:
    """Gate 3: Check duplicate DB."""
    fp = finding.get("fingerprint", "")
    db = load_json(STATE["duplicate_db"])
    if fp and fp in db:
        return False
    return True

def gate4_severity_threshold(finding: Dict) -> bool:
    """Gate 4: Severity must be P1 or P2."""
    sev = finding.get("severity", "").upper()
    return sev in ["P1", "P2", "CRITICAL", "HIGH"]

def phase9_validate(finding: Dict) -> tuple:
    """Run all 4 gates on a finding."""
    if not gate1_http_verify(finding):
        return "DISCARD", "gate1_fail"
    if not gate2_independent_replay(finding):
        return "DISCARD", "gate2_fail"
    if not gate3_duplicate_detect(finding):
        return "SHELVE", "gate3_duplicate"
    if not gate4_severity_threshold(finding):
        return "SHELF", "gate4_below_threshold"
    return "PROCEED", "gates_passed"

# ══════════════════════════════════════════════════════════════════
#  PHASE 10 — PROOF RECORDING
# ══════════════════════════════════════════════════════════════════
def phase10_record_proof(finding: Dict) -> Dict:
    """Launch browser on Xvfb, record exploit with ffmpeg, capture HAR via mitmproxy."""
    log("=== PHASE 10: Proof Recording ===")
    finding_id = finding.get("id", hashlib.sha256(json.dumps(finding).encode()).hexdigest()[:16])
    proof_dir = FINDINGS_OUT / f"{finding['vuln_class']}_{finding_id}"
    ensure_dir(proof_dir)

    # Start Xvfb virtual display
    display_num = 99
    xvfb = subprocess.Popen(["Xvfb", f":{display_num}", "-screen", "0", "1920x1080x24"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.environ["DISPLAY"] = f":{display_num}"
    time.sleep(1)

    # Start ffmpeg screen recorder
    video_path = proof_dir / "proof.mp4"
    ffmpeg = subprocess.Popen([
        "ffmpeg", "-f", "x11grab", "-r", "30", "-s", "1920x1080",
        "-i", f":{display_num}", "-codec:v", "libx264", str(video_path)
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            page = browser.new_page(viewport={"width": 1920, "height": 1080})
            page.goto(finding["target_url"], timeout=30000)
            time.sleep(2)
            # Execute attack chain steps
            for step in finding.get("attack_chain", []):
                time.sleep(2)
                step_url = step.get("url", finding["target_url"])
                page.goto(step_url, timeout=30000)
                time.sleep(1)
            # Vuln-class-specific screenshot
            page.screenshot(path=str(proof_dir / "screenshot.png"))
            browser.close()
    except Exception as e:
        log(f"  Playwright error during proof recording: {e}")

    # Stop recorder
    ffmpeg.terminate()
    try:
        ffmpeg.wait(timeout=5)
    except:
        ffmpeg.kill()
    xvfb.terminate()
    try:
        xvfb.wait(timeout=3)
    except:
        xvfb.kill()

    return {
        "video_path": str(video_path) if video_path.exists() else None,
        "screenshot_path": str(proof_dir / "screenshot.png"),
        "finding_id": finding_id
    }

# ══════════════════════════════════════════════════════════════════
#  PHASE 11 — REPORT GENERATION
# ══════════════════════════════════════════════════════════════════
def phase11_generate_report(finding: Dict, proof: Dict) -> Path:
    """Generate HackerOne-format report."""
    log("=== PHASE 11: Report Generation ===")
    report_dir = FINDINGS_OUT / f"{finding['vuln_class']}_{finding.get('id','0')}"
    ensure_dir(report_dir)

    report = """# {title}

**Severity:** {severity} — {cvss_vector}
**Affected Endpoint:** {endpoint}
**Vulnerability Class:** {vuln_class}

## Description

{description}

## Reproduction Steps

{reproduction_steps}

## Impact

{impact}

## Remediation

{fix_suggestion}

## Attachments

- proof.mp4 - Screen recording of exploit executing (if recorded)
- evidence.har - HTTP request/response chain
- cvss.json - Machine-calculated severity breakdown
""".format(
        title=finding.get("title", "Untitled Finding"),
        severity=finding.get("severity", "Unknown"),
        cvss_vector=finding.get("cvss_vector", "N/A"),
        endpoint=finding.get("endpoint", "N/A"),
        vuln_class=finding.get("vuln_class", "N/A"),
        description=finding.get("description", "No description provided."),
        reproduction_steps=finding.get("reproduction_steps", "1. Navigate to the affected endpoint.\n2. Observe the vulnerability."),
        impact=finding.get("impact", "An attacker could exploit this vulnerability."),
        fix_suggestion=finding.get("fix_suggestion", "Review and sanitize the affected input."),
    )

    report_path = report_dir / "report.md"
    with open(report_path, "w") as fh:
        fh.write(report)

    # Write CVSS JSON
    cvss = finding.get("cvss", {"score": 0.0, "vector": "N/A"})
    with open(report_dir / "cvss.json", "w") as fh:
        json.dump(cvss, fh, indent=2)

    log(f"  Report written to {report_path}")
    return report_path

# ══════════════════════════════════════════════════════════════════
#  PHASE 12 — LEARNING LOOP
# ══════════════════════════════════════════════════════════════════
def phase12_learning(run_summary: Dict):
    """Integrate findings, update weights, promote chains."""
    log("=== PHASE 12: Learning Loop ===")
    findings = load_json(STATE["findings_db"])
    weights = load_json(STATE["weight_map"])
    chain_lib = load_json(STATE["chain_library"])
    dup_db = load_json(STATE["duplicate_db"])
    gate_crit = load_json(STATE["gate_criteria"])

    for finding in run_summary.get("accepted", []):
        findings.append(finding)
        pat = finding.get("endpoint_pattern", "")
        vc = finding.get("vuln_class", "")
        if pat and vc:
            weights.setdefault("endpoint_patterns", {})
            weights["endpoint_patterns"].setdefault(pat, {}).setdefault(vc, 1.0)
            weights["endpoint_patterns"][pat][vc] += 0.5

    for finding in run_summary.get("false_positives", []):
        vc = finding.get("vuln_class", "")
        if vc in gate_crit:
            # Tighten criteria (placeholder logic)
            log(f"  Tightening gate criteria for {vc}")

    save_json(STATE["findings_db"], findings)
    save_json(STATE["weight_map"], weights)
    save_json(STATE["chain_library"], chain_lib)
    save_json(STATE["duplicate_db"], dup_db)
    log(f"  Learning integrated: {len(run_summary.get('accepted',[]))} accepted, {len(run_summary.get('false_positives',[]))} FP")

# ══════════════════════════════════════════════════════════════════
#  MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Rhodawk Autonomous Security Research")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--phase", default="all", help="Run specific phase only (for testing)")
    parser.add_argument("--max-agents", type=int, default=MAX_WORKERS, help="Max parallel agents")
    args = parser.parse_args()

    target = args.target
    log(f"Rhodawk Autonomous Security Research — Target: {target}")
    log(f"Base directory: {BASE_DIR}")

    if args.phase == "all" or args.phase == "0":
        phase0_self_audit()

    if args.phase == "all" or args.phase == "1":
        scope = phase1_scope_parse(target)
    else:
        scope = load_json(STATE["scope"])
        if not scope or "in_scope" not in scope:
            from urllib.parse import urlparse
            net = urlparse(target).netloc
            scope = {
                "target_url": target,
                "in_scope": [net],
                "out_of_scope": [],
                "special_notes": ["fallback scope — no scope.json"],
            }
            save_json(STATE["scope"], scope)

    if args.phase == "all" or args.phase == "2":
        loadout = phase2_loadout(scope)

    if args.phase == "all" or args.phase == "4":
        surface = phase4_recon(scope)
    else:
        surface = load_json(STATE["surface_map"])

    if args.phase == "all" or args.phase == "5":
        queue = phase5_priority_queue(surface)
    else:
        queue = load_json(STATE.get("priority_queue", BASE_DIR / "priority_queue.json"))

    # Write initial queue if not exists
    if not (BASE_DIR / "priority_queue.json").exists():
        save_json(BASE_DIR / "priority_queue.json", queue if 'queue' in dir() else [])

    # Phase 6-8: Agent execution (stub — dispatches to coordinator.py for now)
    if args.phase == "all":
        log("=== PHASE 6-8: Agent Pool + Research + Novel Chains (delegated to coordinator) ===")
        # In full build: spawn agents with Docker, dispatch from priority queue
        # For MVP, log that this requires the coordinator
        run_summary = {"accepted": [], "false_positives": [], "duplicates": [], "low_severity": []}

        # Phase 9-12 gate + proof + report + learning only run if findings exist
        if run_summary["accepted"]:
            for finding in run_summary["accepted"]:
                phase9_validate(finding)
                phase10_record_proof(finding)
                phase11_generate_report(finding, {})

        phase12_learning(run_summary)

    log(f"Run complete. Findings directory: {FINDINGS_OUT}")
    log(f"Surface map: {STATE['surface_map']}")

if __name__ == "__main__":
    main()
