# mitmproxy / mitmweb Fix

## Problem
`mitmweb` fails to start with SQLite operational error on `version_info` table.

## Fix

```bash
cd /root
curl -O https://snapshots.mitmproxy.org/10.3.1/mitmproxy-10.3.1-linux-x86_64.tar.gz
tar xzf mitmproxy-10.3.1-linux-x86_64.tar.gz
sudo mv mitm* /usr/local/bin/
which mitmweb
```

Then verify:
```bash
mitmweb --version
```

Alternative (pip):
```bash
pip3 uninstall mitmproxy  # remove broken install
pip3 install mitmproxy==10.3.1
```

## Integration
mitmweb is called by `phase10_record_proof()` in `rhodawk.py` for HAR export.
It is NOT critical for phase 1-5 (recon), only for proof recording in phase 10.
