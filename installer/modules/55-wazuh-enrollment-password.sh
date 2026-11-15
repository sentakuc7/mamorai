#!/usr/bin/env bash
# MamorAI installer module 55 (EDR-137): Wazuh agent enrollment password, kept by MamorAI for the agent packs.
#   - Uses the existing /var/ossec/etc/authd.pass, or creates one (ROTATE=1 always creates a new one).
#   - Makes sure the manager requires it (<auth><use_password>yes</use_password>).
#   - Hands it to MamorAI on stdin (agent-pack secret registration-password): it is then put into every agent pack
#     automatically. The password is never printed.
#   Agents that are already enrolled are not affected by a new password; only new enrollments use it.
#
#   usage: 55-wazuh-enrollment-password.sh apply|verify
#   env:   MAMORAI_DIR=/opt/edr-console     where MamorAI's docker-compose.yml is
#          ROTATE=1                           create a new password even if authd.pass exists
set -euo pipefail
ACTION="${1:-verify}"
DIR="${MAMORAI_DIR:-/opt/edr-console}"
PASSF=/var/ossec/etc/authd.pass
CONF=/var/ossec/etc/ossec.conf
log() { echo "[55-enrollment-password] $*"; }
cli() { (cd "$DIR" && docker compose exec -T edr-console node server/dist/cli.js "$@"); }
secret_set() { cli agent-pack secret status 2>/dev/null | python3 -c "import json,sys; t=sys.stdin.read(); d=json.loads(t[t.find('{'):]); sys.exit(0 if d['$1']['set'] else 1)" 2>/dev/null; }
[[ $(id -u) -eq 0 ]] || { log "NG: run as root"; exit 1; }
[[ -f "$CONF" ]] || { log "NG: Wazuh manager not found ($CONF)"; exit 1; }

verify() {
  local ok=0
  [[ -s "$PASSF" ]] && log "OK: $PASSF exists" || { log "NG: $PASSF missing"; ok=1; }
  grep -qE '<use_password>yes</use_password>' "$CONF" && log "OK: manager requires the enrollment password" || { log "NG: <use_password> is not yes"; ok=1; }
  if secret_set registration; then log "OK: MamorAI has the enrollment password (agent packs include it)"; else log "NG: MamorAI does not have the enrollment password"; ok=1; fi
  return $ok
}

apply() {
  local restart=0 pw
  if [[ ! -s "$PASSF" || "${ROTATE:-0}" = 1 ]]; then
    pw="$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print(''.join(secrets.choice(a) for _ in range(32)))")"
    umask 027; printf '%s\n' "$pw" > "$PASSF.tmp"; chown root:wazuh "$PASSF.tmp"; chmod 640 "$PASSF.tmp"; mv "$PASSF.tmp" "$PASSF"
    log "created a new enrollment password in $PASSF"; restart=1
  else
    pw="$(head -1 "$PASSF" | tr -d '\r\n')"; log "using the existing enrollment password ($PASSF)"
  fi
  if ! grep -qE '<use_password>yes</use_password>' "$CONF"; then
    cp -p "$CONF" "$CONF.bak-module55"
    if grep -q '<use_password>' "$CONF"; then sed -i 's|<use_password>[^<]*</use_password>|<use_password>yes</use_password>|' "$CONF"
    else sed -i '0,/<auth>/s|<auth>|<auth>\n    <use_password>yes</use_password>|' "$CONF"; fi
    log "manager now requires the enrollment password"; restart=1
  fi
  [[ $restart -eq 1 ]] && { systemctl restart wazuh-manager; log "wazuh-manager restarted"; }
  printf '%s' "$pw" | cli agent-pack secret registration-password >/dev/null && log "handed to MamorAI (agent packs include it from now on)"
  unset pw
  verify
}

case "$ACTION" in apply) apply ;; verify) verify ;; *) echo "usage: $0 apply|verify"; exit 2 ;; esac
