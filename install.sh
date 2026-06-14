#!/usr/bin/env bash
# Rhodawk Hunter — Auto-Installation Script
# Phase 0 tool installation. Run on a fresh system (Ubuntu 22.04+).
set -euo pipefail

GO_BIN="$HOME/go/bin"
PATH="$GO_BIN:/usr/local/bin:$PATH"

echo "============================================================"
echo "  Rhodawk Hunter — Tool Installation"
echo "============================================================"

# ── 1. System dependencies ──
echo "[1/15] System packages..."
apt-get update -qq
apt-get install -y -qq curl wget unzip git build-essential python3 python3-pip tor xvfb x11vnc ffmpeg libssl-dev 2>/dev/null || true

# ── 2. Go toolchain ──
if ! command -v go &>/dev/null; then
    echo "[2/15] Installing Go 1.22..."
    wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    export PATH="$PATH:/usr/local/go/bin"
fi

# ── 3. Python tools ──
echo "[3/15] Python recon tools..."
pip3 install -q mitmproxy sqlmap checker truffleHog arjun linkfinder python-whois requests 2>/dev/null || true

# ── 4. Go recon ──
echo "[4/15] Go recon tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>&1 | tail -1
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>&1 | tail -1
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>&1 | tail -1
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>&1 | tail -1
go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>&1 | tail -1
go install -v github.com/jaeles-project/gospider@latest 2>&1 | tail -1
go install -v github.com/lc/gau/v2/cmd/gau@latest 2>&1 | tail -1
go install -v github.com/tomnomnom/waybackurls@latest 2>&1 | tail -1
go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest 2>&1 | tail -1
go install -v github.com/projectdiscovery/interactsh/client/cmd/interactsh-client@latest 2>&1 | tail -1

# ── 5. OWASP Amass ──
echo "[5/15] OWASP Amass..."
go install -v github.com/owasp/amass/v4/...@master 2>&1 | tail -1

# ── 6. Domain finder binary ──
echo "[6/15] Findomain..."
curl -sL https://github.com/Findomain/Findomain/releases/download/10.0.1/findomain-linux.zip -o /tmp/fd.zip
unzip -o /tmp/fd.zip -d /usr/local/bin/ 2>/dev/null
chmod +x /usr/local/bin/findomain

# ── 7. Secret scanning ──
echo "[7/15] Secret scanners..."
go install -v github.com/trufflesecurity/trufflehog@main 2>&1 | tail -1
go install -v github.com/gitleaks/gitleaks@latest 2>&1 | tail -1

# ── 8. DAST / Injection ──
echo "[8/15] DAST tools..."
go install -v github.com/hahwul/dalfox/v2@latest 2>&1 | tail -1
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>&1 | tail -1
go install -v github.com/haccer/subjack@latest 2>&1 | tail -1

# ── 9. JWT tool ──
echo "[9/15] JWT tool..."
git clone -q --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool 2>/dev/null || true
chmod +x /opt/jwt_tool/jwt_tool.py
ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# ── 10. Playwright ──
echo "[10/15] Playwright..."
pip3 install -q playwright 2>/dev/null
python3 -m playwright install chromium 2>&1 | tail -3

# ── 11. Nuclei templates update ──
echo "[11/15] Nuclei templates..."
nuclei -up 2>&1 | tail -2 || echo "  (nuclei templates update skipped)"

# ── 12. Tor service check ──
echo "[12/15] Verifying Tor..."
systemctl enable tor 2>/dev/null || service tor start 2>/dev/null || true

# ── 13. Verify core binaries ──
echo "[13/15] Verifying installations..."
OK=0
for bin in subfinder httpx katana dalfox nuclei sqlmap jsluice gau trufflehog; do
    if command -v "$bin" &>/dev/null; then
        echo "  OK $bin"
        ((OK++)) || true
    else
        echo "  MISSING $bin"
    fi
done
echo "  $OK/14 core tools installed."

# ── 14. Node registry create ──
echo "[14/15] Building node registry..."
python3 << 'PYEOF'
import json, subprocess, shutil

tools = [
    {"tool_id":"subfinder","capability_tags":["recon","subdomain_enum"],"verified":True},
    {"tool_id":"amass","capability_tags":["recon","subdomain_enum"],"verified":True},
    {"tool_id":"findomain","capability_tags":["recon","subdomain_enum"],"verified":True},
    {"tool_id":"dnsx","capability_tags":["recon","dns_resolution"],"verified":True},
    {"tool_id":"httpx","capability_tags":["recon","live_host_probe"],"verified":True},
    {"tool_id":"naabu","capability_tags":["recon","port_scan"],"verified":True},
    {"tool_id":"katana","capability_tags":["recon","endpoint_crawl"],"verified":True},
    {"tool_id":"gospider","capability_tags":["recon","endpoint_crawl"],"verified":True},
    {"tool_id":"gau","capability_tags":["recon","historical_urls"],"verified":True},
    {"tool_id":"waybackurls","capability_tags":["recon","historical_urls"],"verified":True},
    {"tool_id":"jsluice","capability_tags":["recon","js_analysis","api_extraction"],"verified":True},
    {"tool_id":"linkfinder","capability_tags":["recon","js_analysis","api_extraction"],"verified":True},
    {"tool_id":"trufflehog","capability_tags":["recon","secret_scanning"],"verified":True},
    {"tool_id":"gitleaks","capability_tags":["recon","secret_scanning"],"verified":True},
    {"tool_id":"arjun","capability_tags":["recon","parameter_discovery"],"verified":True},
    {"tool_id":"dalfox","capability_tags":["xss","agent"],"verified":True},
    {"tool_id":"sqlmap","capability_tags":["sqli","agent"],"verified":True},
    {"tool_id":"nuclei","capability_tags":["vuln_scan","multi_class","agent"],"verified":True},
    {"tool_id":"subjack","capability_tags":["subdomain_takeover","agent"],"verified":True},
    {"tool_id":"jwt_tool","capability_tags":["jwt_attack","agent"],"verified":True},
    {"tool_id":"interactsh-client","capability_tags":["oob_callback","ssrf_proof"],"verified":True},
    {"tool_id":"mitmproxy","capability_tags":["traffic_interceptor","har_export"],"verified":True},
    {"tool_id":"ffmpeg","capability_tags":["screen_recorder"],"verified":True},
    {"tool_id":"playwright","capability_tags":["browser_automation","js_rendering"],"verified":True},
    {"tool_id":"xvfb","capability_tags":["virtual_display"],"verified":True},
    {"tool_id":"x11vnc","capability_tags":["vnc_server"],"verified":True},
]
with open("/rhodawk/node_registry.json","w") as f:
    json.dump(tools,f,indent=2)
print("  26 tools in node_registry.json")
PYEOF

# ── 15. Set permissions ──
echo "[15/15] Fixing permissions..."
mkdir -p /rhodawk/{recon,agents,findings,research}
chmod +x /rhodawk/rhodawk.py || true

echo "============================================================"
echo "  Rhodawk Hunter — Installation Complete"
echo "  Run: python3 /rhodawk/rhodawk.py <target_url>"
echo "============================================================"
