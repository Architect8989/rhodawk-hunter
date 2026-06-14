# Rhodawk Hunter — Autonomous Security Research System

12-phase pipeline from scope parse to learning loop. Every tool installed verified, committed to `install.sh`, and auto-registers in `node_registry.json`.

## Quick Start

```bash
# 1. Install (Ubuntu 22.04+)
chmod +x /rhodawk/install.sh
sudo /rhodawk/install.sh

# 2. Run full pipeline
python3 /rhodawk/rhodawk.py https://example.com

# 3. Run single phase
python3 /rhodawk/rhodawk.py https://example.com --phase 4
```

## Architecture

| Phase | Name | Output |
|-------|------|--------|
| 0 | Self-Audit | `node_registry.json` verified |
| 1 | Scope Parse | `scope.json` |
| 2 | Loadout | `loadout.json` |
| 3 | GitHub Discovery | Auto-find missing tools |
| 4 | Recon Pipeline | `surface_map.json` |
| 5 | Priority Queue | Scored endpoint list |
| 6-8 | Agent Pool | Dispatch to solvers |
| 9 | Validation Gates | 4-gate proof system |
| 10 | Proof Recording | `proof.mp4`, HAR, screenshots |
| 11 | Report Gen | HackerOne-format `report.md` |
| 12 | Learning | `weight_map.json`, dedup DB |

## Key Files

- `rhodawk.py` — Main orchestrator (12 phases)
- `node_registry.json` — 26 verified tools with capability tags
- `install.sh` — One-shot auto-install on fresh system
- `install_mitmproxy.sh` — `mitmweb` + `mitmdump` fix
- `coordinator.py` — Parallel job dispatcher (delegates to solvers)
- `findings/` — Proof videos, screenshots, reports
- `research/` — Chain_library, duplicate DB, weight maps

## Node Registry (26 tools)

Recon: subfinder, amass, findomain, dnsx, httpx, naabu, katana, gospider, gau, waybackurls, jsluice, linkfinder, arjun, trufflehog, gitleaks

Agents: dalfox (XSS), sqlmap (SQLi), nuclei (multi-CVE), subjack (takeover), jwt_tool (JWT), interactsh-client (OOB/SSRF)

Proof: mitmproxy (HAR), playwright (automation), xvfb + ffmpeg (screen recording), x11vnc (VNC)

## Running in Docker

```bash
docker build -t rhodawk-hunter .
docker run --rm -v /rhodawk:/rhodawk rhodawk-hunter python3 /rhodawk/rhodawk.py https://example.com
```

## License

Operator-authority. This system is for authorized security research on targets you own or have written permission to test.
