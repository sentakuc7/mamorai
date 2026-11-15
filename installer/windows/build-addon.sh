#!/usr/bin/env bash
# Build the signed MamorAI active-response add-on for Windows (EDR-121).
#   - first run: creates a code-signing certificate for YOUR installation (private key stays in --keys, never in the repo)
#   - signs mamorai-ar.ps1 (Authenticode, osslsigncode) and writes manifest.json with SHA-256 of every file
#   - output folder = what goes into deploy\addon\ next to Install-EdrAgent.ps1 (see docs/host-actions.md)
#
#   - --publish-group G (EDR-169): also copy the signed add-on into the Wazuh shared folder of agent group G
#     (/var/ossec/etc/shared/G/mamorai-addon-*). Agents sync it within minutes; MamorAI's "add-on update"
#     then installs it after checking the hash and that it is signed by the same certificate.
#
# usage: installer/windows/build-addon.sh --keys ~/mamorai-signing --out ./dist/addon [--days 1825] [--timestamp URL] [--publish-group windows]
# needs: openssl, osslsigncode (apt install osslsigncode)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
KEYS="${HOME}/.mamorai-addon-signing"; OUT="./mamorai-addon"; DAYS=1825; TSA=""; GROUPS_PUB=()
while [[ $# -gt 0 ]]; do case "$1" in
  --keys) KEYS="$2"; shift 2;; --out) OUT="$2"; shift 2;; --days) DAYS="$2"; shift 2;; --timestamp) TSA="$2"; shift 2;;
  --publish-group) GROUPS_PUB+=("$2"); shift 2;;
  *) echo "unknown option $1"; exit 2;; esac; done
command -v osslsigncode >/dev/null || { echo "osslsigncode is required (apt install osslsigncode)"; exit 1; }
mkdir -p "$KEYS" "$OUT"; chmod 700 "$KEYS"
if [[ ! -f "$KEYS/signing.key" ]]; then
  echo "[build-addon] creating a code-signing certificate in $KEYS (keep signing.key secret; back it up)"
  ( umask 077
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days "$DAYS" -keyout "$KEYS/signing.key" -out "$KEYS/signing.crt" \
    -subj "/CN=MamorAI add-on signing ($(hostname -s))/O=MamorAI local installation" \
    -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=codeSigning" 2>/dev/null )
fi
VER=$(grep -oP "(?<=\\\$AddonVersion = ')[0-9.]+" "$HERE/addon/mamorai-ar.ps1")
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sed 's/\r$//; s/$/\r/' "$HERE/addon/mamorai-ar.ps1" > "$tmp/mamorai-ar.ps1"   # CRLF
args=(sign -certs "$KEYS/signing.crt" -key "$KEYS/signing.key" -h sha256 -n "MamorAI active-response add-on $VER" -in "$tmp/mamorai-ar.ps1" -out "$OUT/mamorai-ar.ps1")
[[ -n "$TSA" ]] && args+=(-t "$TSA")
rm -f "$OUT/mamorai-ar.ps1"; osslsigncode "${args[@]}" >/dev/null
osslsigncode verify -in "$OUT/mamorai-ar.ps1" -CAfile "$KEYS/signing.crt" >/dev/null || { echo "signature verification failed"; exit 1; }
cp "$HERE/addon/mamorai-ar.cmd" "$OUT/mamorai-ar.cmd"
cp "$HERE/addon/Install-MamoraiAddon.ps1" "$OUT/Install-MamoraiAddon.ps1"
openssl x509 -in "$KEYS/signing.crt" -outform DER -out "$OUT/mamorai-addon-signing.cer"
THUMB=$(openssl x509 -in "$KEYS/signing.crt" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
python3 - "$OUT" "$VER" "$THUMB" <<'PY'
import hashlib, json, os, sys
out, ver, thumb = sys.argv[1:4]
files = {f: hashlib.sha256(open(os.path.join(out, f), "rb").read()).hexdigest() for f in ("mamorai-ar.cmd", "mamorai-ar.ps1", "mamorai-addon-signing.cer")}
json.dump({"name": "mamorai-ar", "version": ver, "signer_thumbprint": thumb, "files": files}, open(os.path.join(out, "manifest.json"), "w"), indent=2)
PY
echo "[build-addon] v$VER signed (signer $THUMB) → $OUT"
ls -l "$OUT"
for g in "${GROUPS_PUB[@]}"; do
  [[ "$g" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "invalid group name $g"; exit 2; }
  d="/var/ossec/etc/shared/$g"
  [[ -d "$d" ]] || { echo "[build-addon] NG: $d not found (agent group $g does not exist on this manager)"; exit 1; }
  # the Windows agent writes shared files in text mode (LF -> CRLF; a CRLF file would become CR CR LF and fail the
  # hash and signature check, a lab PC, 2026-11-06): publish with LF so the PC ends up with the signed CRLF bytes
  sed 's/\r$//' "$OUT/mamorai-ar.ps1" > "$d/mamorai-addon-ar.ps1"; chown wazuh:wazuh "$d/mamorai-addon-ar.ps1"; chmod 0640 "$d/mamorai-addon-ar.ps1"
  sed 's/\r$//' "$OUT/mamorai-ar.cmd" > "$d/mamorai-addon-ar.cmd"; chown wazuh:wazuh "$d/mamorai-addon-ar.cmd"; chmod 0640 "$d/mamorai-addon-ar.cmd"
  rm -f "$d/mamorai-addon-signing.cer"   # binary files are not synced by Wazuh; the signer comes from the signature itself
  install -m 0640 -o wazuh -g wazuh "$OUT/manifest.json" "$d/mamorai-addon-manifest.json"
  echo "[build-addon] published v$VER to agent group $g ($d); agents pick it up at their next sync"
done
