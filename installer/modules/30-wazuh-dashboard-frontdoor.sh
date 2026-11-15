#!/usr/bin/env bash
# MamorAI installer module 30: Wazuh dashboard behind the MamorAI front door (EDR-90)
#
#   The Wazuh dashboard has no MFA of its own. This module closes it to 127.0.0.1, serves it under /wazuh and
#   switches it to OpenSearch Security "proxy" authentication, so the only way in is through MamorAI
#   (password + TOTP). MamorAI forwards the signed-in user as x-proxy-user / x-proxy-roles.
#
#   usage: 30-wazuh-dashboard-frontdoor.sh apply|verify|revert
#   env:   MAMORAI_DASHBOARD_BASEPATH (default /wazuh)  MAMORAI_BACKUP_DIR (default /var/lib/mamorai/backup)
#   break-glass: `revert` restores the dashboard's own login (direct access on its port again).
set -euo pipefail
ACTION="${1:-verify}"
BASEPATH="${MAMORAI_DASHBOARD_BASEPATH:-/wazuh}"
BK_ROOT="${MAMORAI_BACKUP_DIR:-/var/lib/mamorai/backup}/dashboard-frontdoor"
DASH_YML=/etc/wazuh-dashboard/opensearch_dashboards.yml
SEC_TOOLS=/usr/share/wazuh-indexer/plugins/opensearch-security/tools
CERTS=/etc/wazuh-indexer/certs
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
PORT=$(awk -F': *' '/^server.port:/{print $2}' "$DASH_YML"); PORT=${PORT:-443}
log() { echo "[30-dashboard-frontdoor] $*"; }
secadmin() { bash "$SEC_TOOLS/securityadmin.sh" -icl -nhnv -h 127.0.0.1 -cacert "$CERTS/root-ca.pem" -cert "$CERTS/admin.pem" -key "$CERTS/admin-key.pem" "$@" >/tmp/mamorai-secadmin.log 2>&1 || { tail -20 /tmp/mamorai-secadmin.log; return 1; }; }

verify() {
  local ok=0
  if ss -tlnH "sport = :$PORT" | grep -qvE "127\.0\.0\.1:$PORT|\[::1\]:$PORT"; then log "NG: dashboard listens on a non-loopback address"; ok=1; else log "OK: dashboard listens on loopback only"; fi
  local c1 c2
  c1=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$PORT$BASEPATH/api/status")
  c2=$(curl -sk -o /dev/null -w '%{http_code}' -H "x-proxy-user: mamorai-verify" -H "x-proxy-roles: readall" -H "x-forwarded-for: 127.0.0.1" "https://127.0.0.1:$PORT$BASEPATH/api/status")
  if [[ "$c1" == "401" && "$c2" == "200" ]]; then log "OK: no header → 401, proxy header → 200"; else log "NG: no header → $c1, proxy header → $c2 (want 401 / 200)"; ok=1; fi
  return $ok
}

apply() {
  local ts; ts=$(date +%Y%m%d%H%M%S); local bk="$BK_ROOT/$ts"; mkdir -p "$bk"; chmod 700 "$BK_ROOT" "$bk"
  cp -p "$DASH_YML" "$bk/opensearch_dashboards.yml"
  log "backing up the live security config to $bk"
  secadmin -backup "$bk/security"
  # 1) indexer: trust x-proxy-user only when the request comes from the local dashboard (loopback)
  python3 - "$bk/security/config.yml" "$bk/config.new.yml" <<'PY'
import sys, yaml
src, dst = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(src))
dyn = d["config"]["dynamic"]
dyn.setdefault("http", {})["xff"] = {"enabled": True, "internalProxies": r"127\.0\.0\.1|0:0:0:0:0:0:0:1|::1", "remoteIpHeader": "x-forwarded-for"}
p = dyn["authc"].setdefault("proxy_auth_domain", {})
p.update({"description": "MamorAI front door (password + TOTP in MamorAI)", "http_enabled": True, "transport_enabled": False, "order": 0,
          "http_authenticator": {"type": "proxy", "challenge": False, "config": {"user_header": "x-proxy-user", "roles_header": "x-proxy-roles"}},
          "authentication_backend": {"type": "noop"}})
# basic_internal_auth_domain stays as is: service accounts (kibanaserver, MamorAI) keep using basic auth
yaml.safe_dump(d, open(dst, "w"), sort_keys=False)
PY
  log "uploading security config (xff + proxy auth)"
  secadmin -f "$bk/config.new.yml" -t config
  # 2) dashboard: loopback only, base path, proxy auth
  python3 - "$DASH_YML" "$BASEPATH" <<'PY'
import sys, re
path, base = sys.argv[1], sys.argv[2]
lines = open(path).read().splitlines()
want = {
  "server.host": "127.0.0.1",
  "server.basePath": f'"{base}"',
  "server.rewriteBasePath": "true",
  "opensearch.requestHeadersAllowlist": '["securitytenant","Authorization","x-forwarded-for","x-proxy-user","x-proxy-roles"]',
  "opensearch_security.auth.type": '"proxy"',
  "opensearch_security.proxycache.user_header": '"x-proxy-user"',
  "opensearch_security.proxycache.roles_header": '"x-proxy-roles"',
}
seen = set(); out = []
for ln in lines:
  m = re.match(r"^([A-Za-z0-9_.]+):", ln)
  if m and m.group(1) in want:
    k = m.group(1); out.append(f"{k}: {want[k]}"); seen.add(k)
  else: out.append(ln)
out.append("# --- MamorAI front door (installer module 30) ---") if len(seen) < len(want) else None
for k, v in want.items():
  if k not in seen: out.append(f"{k}: {v}")
open(path, "w").write("\n".join(out) + "\n")
PY
  systemctl restart wazuh-dashboard
  log "waiting for the dashboard"
  for i in $(seq 1 60); do curl -sk -o /dev/null "https://127.0.0.1:$PORT$BASEPATH/api/status" && break; sleep 3; done
  sleep 5
  echo "$bk" > "$BK_ROOT/LATEST"
  verify
}

revert() {
  local bk; bk=$(cat "$BK_ROOT/LATEST" 2>/dev/null || true)
  [[ -n "$bk" && -d "$bk" ]] || { log "no backup to revert to"; exit 1; }
  log "restoring $bk"
  cp -p "$bk/opensearch_dashboards.yml" "$DASH_YML"
  secadmin -f "$bk/security/config.yml" -t config
  systemctl restart wazuh-dashboard
  log "reverted: the dashboard has its own login again on port $PORT"
}

case "$ACTION" in
  apply) apply ;;
  verify) verify ;;
  revert) revert ;;
  *) echo "usage: $0 apply|verify|revert"; exit 2 ;;
esac
