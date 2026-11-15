#!/usr/bin/env bash
# EDR-171: publish the Windows agent pack (without secrets) into the Wazuh shared folder of agent group(s), so that
# MamorAI can update the pack on PCs remotely (add-on >= 1.3.3, op "pack-update <rev>").
#   input : request JSON written by MamorAI through the host bridge (installer/modules/62-host-bridge.sh, task pack-publish):
#           {"rev":17,"addon_version":"1.3.3","groups":["windows"],"files":{"Install-EdrAgent.ps1":"<b64>",
#            "Install-MamoraiAddon.ps1":"<b64>","config.json":"<b64>","pack.json":"<b64>"}}
#   output: /var/ossec/etc/shared/<group>/mamorai-pack-{Install-EdrAgent.ps1,Install-MamoraiAddon.ps1,config.json,pack.json}
#           and mamorai-pack-manifest.json (written last). Both scripts are Authenticode-signed with the add-on key, so
#           the endpoint only runs them when they are signed by the same certificate as its installed add-on.
#   Refuses a config.json that carries the enrollment password or a Tailscale key (they are never put in the shared folder).
#
# usage: publish-pack.sh <request.json> [--keys /root/mamorai-signing]
set -euo pipefail
REQ="${1:?request.json}"; shift || true
KEYS=/root/mamorai-signing
while [[ $# -gt 0 ]]; do case "$1" in --keys) KEYS="$2"; shift 2;; *) echo "unknown option $1"; exit 2;; esac; done
[[ -f "$KEYS/signing.key" && -f "$KEYS/signing.crt" ]] || { echo "NG: signing key not found in $KEYS (installer/windows/build-addon.sh creates it)"; exit 1; }
command -v osslsigncode >/dev/null || { echo "NG: osslsigncode is required"; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT; chmod 700 "$tmp"
python3 - "$REQ" "$tmp" <<'PY'
import base64, json, re, sys, os
req, out = sys.argv[1:3]
d = json.load(open(req))
rev = d.get("rev"); assert isinstance(rev, int) and 0 < rev < 10**6, "bad rev"
av = str(d.get("addon_version") or "")
assert re.fullmatch(r"\d+\.\d+\.\d+", av), "bad addon_version"
groups = d.get("groups") or ["windows"]
assert all(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", g) for g in groups), "bad group"
names = ["Install-EdrAgent.ps1", "Install-MamoraiAddon.ps1", "config.json", "pack.json"]
files = d.get("files") or {}
assert sorted(files) == sorted(names), "unexpected file list"
for n in names:
    b = base64.b64decode(files[n], validate=True)
    assert 0 < len(b) < 512 * 1024, f"{n}: size"
    open(os.path.join(out, n), "wb").write(b)
c = json.load(open(os.path.join(out, "config.json")))
assert not c.get("registrationPassword") and not c.get("tailscaleAuthKey"), "config.json carries a secret: refused"
p = json.load(open(os.path.join(out, "pack.json")))
assert int(p.get("rev")) == rev and not p.get("contains_secrets"), "pack.json mismatch"
open(os.path.join(out, "meta"), "w").write(f"{rev}\n{av}\n{' '.join(groups)}\n")
PY
REV=$(sed -n 1p "$tmp/meta"); AV=$(sed -n 2p "$tmp/meta"); GROUPS_PUB=$(sed -n 3p "$tmp/meta")
mkdir -p "$tmp/crlf" "$tmp/signed"   # osslsigncode picks the file type from the extension: keep ".ps1"
for f in Install-EdrAgent.ps1 Install-MamoraiAddon.ps1; do
  sed 's/\r$//; s/$/\r/' "$tmp/$f" > "$tmp/crlf/$f"
  osslsigncode sign -certs "$KEYS/signing.crt" -key "$KEYS/signing.key" -h sha256 -n "MamorAI agent pack r$REV" -in "$tmp/crlf/$f" -out "$tmp/signed/$f" >/dev/null
  osslsigncode verify -in "$tmp/signed/$f" -CAfile "$KEYS/signing.crt" >/dev/null || { echo "NG: signature verification failed for $f"; exit 1; }
  mv -f "$tmp/signed/$f" "$tmp/$f"
done
THUMB=$(openssl x509 -in "$KEYS/signing.crt" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
python3 - "$tmp" "$REV" "$AV" "$THUMB" <<'PY'
import hashlib, json, os, sys
d, rev, av, th = sys.argv[1:5]
# hashes of the bytes the PC will have: the Windows agent writes shared files in text mode (LF -> CRLF)
def crlf(b): return b.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
m = {"name": "mamorai-pack", "os": "windows", "rev": int(rev), "addon_version": av, "signer_thumbprint": th,
     "files": {n: hashlib.sha256(crlf(open(os.path.join(d, n), "rb").read())).hexdigest() for n in ("Install-EdrAgent.ps1", "Install-MamoraiAddon.ps1", "config.json", "pack.json")}}
json.dump(m, open(os.path.join(d, "manifest.json"), "w"), indent=2)
PY
ADDON="${MAMORAI_DIR:-/opt/edr-console}/addon"
AV_HAVE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version",""))' "$ADDON/manifest.json" 2>/dev/null || true)
[[ "$AV_HAVE" == "$AV" ]] || { echo "NG: the add-on in $ADDON is v${AV_HAVE:-?}, the pack expects v$AV (run build-addon.sh first)"; exit 1; }
for g in $GROUPS_PUB; do
  sd="/var/ossec/etc/shared/$g"
  [[ -d "$sd" ]] || { echo "NG: $sd not found (agent group $g)"; exit 1; }
  # the add-on of the same version goes along (same names as build-addon.sh --publish-group)
  # written with LF: the Windows agent turns LF into CRLF when it saves shared files (see build-addon.sh)
  put() { sed 's/\r$//' "$1" > "$2"; chown wazuh:wazuh "$2"; chmod 0640 "$2"; }
  put "$ADDON/mamorai-ar.ps1" "$sd/mamorai-addon-ar.ps1"
  put "$ADDON/mamorai-ar.cmd" "$sd/mamorai-addon-ar.cmd"
  install -m 0640 -o wazuh -g wazuh "$ADDON/manifest.json" "$sd/mamorai-addon-manifest.json"
  for f in Install-EdrAgent.ps1 Install-MamoraiAddon.ps1 config.json pack.json; do put "$tmp/$f" "$sd/mamorai-pack-$f"; done
  install -m 0640 -o wazuh -g wazuh "$tmp/manifest.json" "$sd/mamorai-pack-manifest.json"
  echo "published pack r$REV (add-on $AV) to agent group $g"
done
