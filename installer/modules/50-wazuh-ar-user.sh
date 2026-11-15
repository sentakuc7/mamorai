#!/usr/bin/env bash
# MamorAI installer module 50 (EDR-121): a Wazuh API user that may ONLY run active responses.
#   MamorAI's normal Wazuh API user is read-only. Host actions on Windows endpoints (stop a service, block a port / IP,
#   isolate) are sent as active responses with this separate user, and only after a human approved them in MamorAI.
#   Creates: policy "mamorai_ar_policy" (active-response:command on agent:id:*), role "mamorai_ar", user "mamorai-ar"
#   and writes WAZUH_AR_USER / WAZUH_AR_PASSWORD into MamorAI's .env (the password is never printed).
#
#   usage: 50-wazuh-ar-user.sh apply|verify|revert
#   env:   MAMORAI_ENV=/opt/edr-console/.env            MamorAI env file to update
#          WAZUH_API=https://127.0.0.1:55000
#          WAZUH_ADMIN_USER / WAZUH_ADMIN_PASSWORD        Wazuh API admin (default: read from WAZUH_PASSWORDS_FILE)
#          WAZUH_PASSWORDS_FILE=/root/wazuh/wazuh-install-files/wazuh-passwords.txt  (written by the Wazuh all-in-one installer)
set -euo pipefail
ACTION="${1:-verify}"
ENVF="${MAMORAI_ENV:-/opt/edr-console/.env}"
API="${WAZUH_API:-https://127.0.0.1:55000}"
PWF="${WAZUH_PASSWORDS_FILE:-/root/wazuh/wazuh-install-files/wazuh-passwords.txt}"
U=mamorai-ar; ROLE=mamorai_ar; POL=mamorai_ar_policy
log() { echo "[50-wazuh-ar-user] $*"; }

admin_creds() {
  if [[ -n "${WAZUH_ADMIN_USER:-}" && -n "${WAZUH_ADMIN_PASSWORD:-}" ]]; then AU="$WAZUH_ADMIN_USER"; AP="$WAZUH_ADMIN_PASSWORD"; return; fi
  [[ -r "$PWF" ]] || { log "NG: set WAZUH_ADMIN_USER/WAZUH_ADMIN_PASSWORD or WAZUH_PASSWORDS_FILE"; exit 1; }
  AU=wazuh
  AP=$(awk "/api_username: '?wazuh'?\$/{getline; sub(/.*api_password: /,\"\"); gsub(/'/,\"\"); print; exit}" "$PWF")
  [[ -n "$AP" ]] || { log "NG: could not read the wazuh API password from $PWF"; exit 1; }
}
tok() { curl -sk -u "$AU:$AP" -X POST "$API/security/user/authenticate?raw=true"; }
call() { local m=$1 p=$2; shift 2; curl -sk -X "$m" -H "Authorization: Bearer $T" -H "Content-Type: application/json" "$API$p" "$@"; }
jq_py() { python3 -c "import json,sys; d=json.load(sys.stdin); $1"; }
id_of() { # $1=endpoint $2=field $3=value
  call GET "$1?limit=500" | jq_py "print(next((str(x['id']) for x in d['data']['affected_items'] if x.get('$2')=='$3'), ''))"
}
env_get() { grep -E "^$1=" "$ENVF" 2>/dev/null | head -1 | cut -d= -f2-; }
env_set() { # never echoes the value
  local k=$1 v=$2 tmp; tmp=$(mktemp); chmod 600 "$tmp"
  grep -vE "^$k=" "$ENVF" > "$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$k" "$v" >> "$tmp"; cat "$tmp" > "$ENVF"; rm -f "$tmp"
}

verify() {
  admin_creds; T=$(tok); local ok=0
  [[ -n "$(id_of /security/users username $U)" ]] && log "OK: user $U exists" || { log "NG: user $U missing"; ok=1; }
  [[ -n "$(id_of /security/roles name $ROLE)" ]] && log "OK: role $ROLE exists" || { log "NG: role $ROLE missing"; ok=1; }
  if [[ -n "$(env_get WAZUH_AR_PASSWORD)" ]]; then
    local t2; t2=$(curl -sk -u "$U:$(env_get WAZUH_AR_PASSWORD)" -X POST "$API/security/user/authenticate?raw=true")
    [[ ${#t2} -gt 100 ]] && log "OK: $U can authenticate with the password in $ENVF" || { log "NG: $U cannot authenticate with the password in $ENVF"; ok=1; }
  else log "NG: WAZUH_AR_PASSWORD not set in $ENVF"; ok=1; fi
  return $ok
}

apply() {
  admin_creds; T=$(tok); [[ ${#T} -gt 100 ]] || { log "NG: Wazuh API admin login failed"; exit 1; }
  local pid rid uid pw
  # Wazuh refuses a second policy with the same body: reuse any policy that grants exactly active-response:command on agent:id:*
  pid=$(call GET "/security/policies?limit=500" | jq_py "print(next((str(x['id']) for x in d['data']['affected_items'] if sorted(x['policy'].get('actions',[]))==['active-response:command'] and x['policy'].get('resources')==['agent:id:*'] and x['policy'].get('effect')=='allow'), ''))")
  [[ -n "$pid" ]] || pid=$(call POST /security/policies -d "{\"name\":\"$POL\",\"policy\":{\"actions\":[\"active-response:command\"],\"resources\":[\"agent:id:*\"],\"effect\":\"allow\"}}" | jq_py "print(d['data']['affected_items'][0]['id'])")
  log "policy id $pid (active-response:command on agent:id:*)"
  rid=$(id_of /security/roles name $ROLE)
  [[ -n "$rid" ]] || rid=$(call POST /security/roles -d "{\"name\":\"$ROLE\"}" | jq_py "print(d['data']['affected_items'][0]['id'])")
  call POST "/security/roles/$rid/policies?policy_ids=$pid" >/dev/null
  # 32 chars with upper, lower, digit and symbol (Wazuh password policy)
  pw="$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Ma'+''.join(secrets.choice(a) for _ in range(26))+'7_!x')")"
  uid=$(id_of /security/users username $U)
  if [[ -z "$uid" ]]; then
    uid=$(call POST /security/users -d "{\"username\":\"$U\",\"password\":\"$pw\"}" | jq_py "print(d['data']['affected_items'][0]['id'])")
  else
    call PUT "/security/users/$uid" -d "{\"password\":\"$pw\"}" >/dev/null
  fi
  call POST "/security/users/$uid/roles?role_ids=$rid" >/dev/null
  [[ -f "$ENVF" ]] || { log "NG: $ENVF not found (set MAMORAI_ENV)"; exit 1; }
  cp -p "$ENVF" "$ENVF.bak-module50"
  env_set WAZUH_AR_USER "$U"; env_set WAZUH_AR_PASSWORD "$pw"; unset pw
  log "applied: user $U (role $ROLE → active-response:command only). Restart MamorAI to load the credentials: docker compose up -d"
  verify
}

revert() {
  admin_creds; T=$(tok)
  local uid rid pid
  uid=$(id_of /security/users username $U); [[ -n "$uid" ]] && call DELETE "/security/users?user_ids=$uid" >/dev/null && log "deleted user $U"
  rid=$(id_of /security/roles name $ROLE); [[ -n "$rid" ]] && call DELETE "/security/roles?role_ids=$rid" >/dev/null && log "deleted role $ROLE"
  pid=$(id_of /security/policies name $POL); [[ -n "$pid" ]] && call DELETE "/security/policies?policy_ids=$pid" >/dev/null && log "deleted policy $POL"   # a reused built-in policy is left alone
  if [[ -f "$ENVF" ]]; then local tmp; tmp=$(mktemp); grep -vE '^WAZUH_AR_(USER|PASSWORD)=' "$ENVF" > "$tmp" || true; cat "$tmp" > "$ENVF"; rm -f "$tmp"; log "removed WAZUH_AR_* from $ENVF"; fi
}

case "$ACTION" in apply) apply ;; verify) verify ;; revert) revert ;; *) echo "usage: $0 apply|verify|revert"; exit 2 ;; esac
