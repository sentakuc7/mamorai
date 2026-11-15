#!/usr/bin/env bash
# MamorAI installer module 60 (EDR-139): Tailscale on the Wazuh manager — optional "connection mode".
#   Use it when laptops that leave the office or servers outside the LAN (cloud) must reach the manager without
#   opening Wazuh to the internet. Skip it for LAN-only setups.
#
#   apply:
#     1. reads the Tailscale auth key the user prepared (docs/setup/01-prepare-tailscale.ai.md):
#        from TS_AUTHKEY_FILE, or stdin, or an interactive hidden prompt. The key is never printed or logged.
#     2. installs Tailscale (official script) and joins the tailnet (no Tailscale SSH, no DNS changes)
#     3. allows Wazuh (1514/1515), MamorAI (8444) and SSH (22) on the tailscale0 interface only (ufw or firewalld)
#     4. tells MamorAI the manager's tailnet address and hands it the key (encrypted there) → every agent pack
#        gets the key automatically, laptops / cloud servers join the tailnet while installing the agent
#   verify: Tailscale is up, firewall rules exist, MamorAI has the address and the key
#   revert: removes the firewall rules, logs out of the tailnet, removes the address and the key from MamorAI
#
#   prepare: (EDR-149) install Tailscale and open the tailscale0 firewall rules only — the key is entered later in
#            MamorAI (設定 › エージェントパック › 秘密情報); the host bridge (module 62) then runs `apply` with it
#
#   usage: 60-tailscale.sh prepare|apply|verify|revert
#   env:   MAMORAI_DIR=/opt/edr-console    where MamorAI's docker-compose.yml is
#          TS_AUTHKEY_FILE=<file>            file that holds the key (deleted after use when TS_AUTHKEY_FILE_DELETE=1)
#          TS_EXPIRES=YYYY-MM-DD             expiry of the key (MamorAI warns 14 days before)
#          TS_HOSTNAME=<name>                tailnet name of the manager (default: hostname -s)
#          TS_TAGS=tag:wazuh                 optional, only if the tailnet ACL defines this tag
#          TS_SKIP_STORE=1                   do not hand the key to MamorAI (it already has it: called by the host bridge)
set -euo pipefail
ACTION="${1:-verify}"
DIR="${MAMORAI_DIR:-/opt/edr-console}"
PORTS=(1514 1515 8444 22)
log() { echo "[60-tailscale] $*"; }
cli() { (cd "$DIR" && docker compose exec -T edr-console node server/dist/cli.js "$@"); }
have_mamorai() { [[ -f "$DIR/docker-compose.yml" ]] && (cd "$DIR" && docker compose ps --status running --services 2>/dev/null | grep -qx edr-console); }
[[ $(id -u) -eq 0 ]] || { log "NG: run as root"; exit 1; }

read_key() {
  local k=""
  if [[ -n "${TS_AUTHKEY_FILE:-}" ]]; then k="$(head -1 "$TS_AUTHKEY_FILE" | tr -d '\r\n ')"; [[ "${TS_AUTHKEY_FILE_DELETE:-0}" = 1 ]] && rm -f "$TS_AUTHKEY_FILE"
  elif [[ ! -t 0 ]]; then k="$(head -1 | tr -d '\r\n ')"
  else read -r -s -p "Tailscale auth key (tskey-auth-...): " k; echo; fi
  [[ "$k" =~ ^tskey-[A-Za-z0-9_-]{8,200}$ ]] || { log "NG: that does not look like a Tailscale auth key (tskey-...)"; exit 1; }
  printf '%s' "$k"
}

fw_apply() {
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    for p in "${PORTS[@]}"; do ufw allow in on tailscale0 to any port "$p" proto tcp comment "mamorai-tailscale" >/dev/null; done
    log "ufw: allowed ${PORTS[*]}/tcp on tailscale0"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --zone=internal --add-interface=tailscale0 >/dev/null 2>&1 || true
    for p in "${PORTS[@]}"; do firewall-cmd --permanent --zone=internal --add-port="$p/tcp" >/dev/null; done
    firewall-cmd --reload >/dev/null; log "firewalld: tailscale0 in zone internal with ${PORTS[*]}/tcp"
  else log "no active ufw / firewalld: nothing to open (consider enabling a host firewall)"; fi
}
fw_revert() {
  if command -v ufw >/dev/null 2>&1; then for p in "${PORTS[@]}"; do ufw delete allow in on tailscale0 to any port "$p" proto tcp >/dev/null 2>&1 || true; done; fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    for p in "${PORTS[@]}"; do firewall-cmd --permanent --zone=internal --remove-port="$p/tcp" >/dev/null 2>&1 || true; done
    firewall-cmd --permanent --zone=internal --remove-interface=tailscale0 >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null || true
  fi
}

verify() {
  local ok=0 tip
  if command -v tailscale >/dev/null 2>&1 && tailscale status >/dev/null 2>&1; then tip="$(tailscale ip -4 | head -1)"; log "OK: in the tailnet as $tip"; else log "NG: Tailscale is not up"; ok=1; tip=""; fi
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw status | grep -q "1514/tcp on tailscale0" && log "OK: ufw allows Wazuh on tailscale0" || { log "NG: ufw rule for tailscale0 missing"; ok=1; }
  fi
  if have_mamorai; then
    local st; st="$(cli agent-pack show 2>/dev/null || true)"
    if [[ -n "$tip" ]] && echo "$st" | grep -q "\"tailnet\": \"$tip\""; then log "OK: MamorAI knows the manager's tailnet address"; else log "NG: MamorAI's agent pack settings do not have $tip"; ok=1; fi
    if cli agent-pack secret status 2>/dev/null | python3 -c "import json,sys; t=sys.stdin.read(); d=json.loads(t[t.find('{'):]); sys.exit(0 if d['tailscale']['set'] else 1)"; then log "OK: MamorAI has the Tailscale key (agent packs include it)"; else log "NG: MamorAI does not have the Tailscale key"; ok=1; fi
  else log "MamorAI is not running in $DIR: skipped the MamorAI checks"; fi
  return $ok
}

install_ts() {
  if ! command -v tailscale >/dev/null 2>&1; then
    log "installing Tailscale (https://tailscale.com/install.sh)"
    curl -fsSL https://tailscale.com/install.sh | sh >/dev/null || { log "NG: Tailscale install failed"; exit 1; }
  fi
  systemctl enable --now tailscaled >/dev/null 2>&1 || true
}

prepare() {
  install_ts
  fw_apply
  if tailscale status >/dev/null 2>&1; then log "already in the tailnet as $(tailscale ip -4 | head -1)"
  else log "Tailscale is installed; the server joins when the key is entered in MamorAI (設定 › エージェントパック › 秘密情報)"; fi
}

apply() {
  local key tip
  key="$(read_key)"
  install_ts
  if tailscale status >/dev/null 2>&1; then log "already in a tailnet: kept as it is"
  else
    tailscale up --authkey "$key" --hostname "${TS_HOSTNAME:-$(hostname -s)}" --ssh=false --accept-dns=false ${TS_TAGS:+--advertise-tags="$TS_TAGS"} >/dev/null || { log "NG: tailscale up failed (key expired or already used?)"; exit 1; }
    log "joined the tailnet"
  fi
  tip="$(tailscale ip -4 | head -1)"; log "manager tailnet address: $tip"
  fw_apply
  if have_mamorai; then
    cli agent-pack set "{\"manager\":{\"tailnet\":\"$tip\"}}" >/dev/null && log "MamorAI: agent pack settings now use $tip"
    if [[ "${TS_SKIP_STORE:-0}" != 1 ]]; then printf '%s' "$key" | cli agent-pack secret tailscale-key ${TS_EXPIRES:+"$TS_EXPIRES"} >/dev/null && log "MamorAI: Tailscale key stored (encrypted); agent packs include it from now on"; fi
  else log "MamorAI is not running in $DIR yet: run this module again after MamorAI is up (it is idempotent)"; fi
  unset key
  verify
}

revert() {
  fw_revert
  command -v tailscale >/dev/null 2>&1 && tailscale logout >/dev/null 2>&1 || true
  if have_mamorai; then cli agent-pack set '{"manager":{"tailnet":""}}' >/dev/null || true; cli agent-pack secret clear tailscale-key >/dev/null || true; fi
  log "reverted: firewall rules removed, logged out of the tailnet, MamorAI no longer uses Tailscale (the package stays installed)"
}

case "$ACTION" in prepare) prepare ;; apply) apply ;; verify) verify ;; revert) revert ;; *) echo "usage: $0 prepare|apply|verify|revert"; exit 2 ;; esac
