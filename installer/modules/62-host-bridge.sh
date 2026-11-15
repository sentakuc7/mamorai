#!/usr/bin/env bash
# MamorAI installer module 62 (EDR-149): host bridge — lets MamorAI ask the host for a few fixed root tasks.
#   MamorAI runs in a read-only container as a non-root user and cannot change the host. Some settings made in the
#   MamorAI screen still need the host, e.g. "join this server to the tailnet with the key I just entered".
#   The bridge is a fixed list of tasks, not a shell:
#     - MamorAI writes <dir>/requests/<task>.json (mode 600, owned by the container user)
#     - systemd (mamorai-host-bridge.path) starts mamorai-host-bridge.service (root, oneshot)
#     - the helper takes the request away at once (secrets never stay on disk), runs the task,
#       writes <dir>/results/<task>.json (no secrets) and audits it in the journal (tag mamorai-host-bridge)
#   tasks: tailscale-join  → installer/modules/60-tailscale.sh apply with the key from the request
#          pack-publish    → installer/windows/publish-pack.sh (EDR-171: Windows pack without secrets → Wazuh shared folder)
#
#   usage: 62-host-bridge.sh apply|verify|revert
#   env:   MAMORAI_DIR=/opt/edr-console
set -euo pipefail
ACTION="${1:-verify}"
DIR="${MAMORAI_DIR:-/opt/edr-console}"
B=/var/lib/mamorai/host-bridge
BIN=/usr/local/sbin/mamorai-host-bridge
UNIT=/etc/systemd/system/mamorai-host-bridge
log() { echo "[62-host-bridge] $*"; }
[[ $(id -u) -eq 0 ]] || { log "NG: run as root"; exit 1; }

container_ids() { # uid:gid of the user inside the MamorAI container (alpine "app")
  local ids
  ids=$(cd "$DIR" && docker compose exec -T edr-console sh -c 'echo "$(id -u):$(id -g)"' 2>/dev/null | tr -d '\r' || true)
  [[ "$ids" =~ ^[0-9]+:[0-9]+$ ]] && echo "$ids" || echo "100:101"
}

verify() {
  local ok=0
  [[ -x "$BIN" ]] && log "OK: helper $BIN" || { log "NG: helper missing"; ok=1; }
  systemctl is-enabled -q mamorai-host-bridge.path 2>/dev/null && systemctl is-active -q mamorai-host-bridge.path && log "OK: mamorai-host-bridge.path is active" || { log "NG: mamorai-host-bridge.path is not active"; ok=1; }
  [[ -d "$B/requests" && -d "$B/results" ]] && log "OK: $B" || { log "NG: $B missing"; ok=1; }
  if (cd "$DIR" && docker compose exec -T edr-console sh -c 'test -w /app/host-bridge/requests') 2>/dev/null; then log "OK: MamorAI can write requests"; else log "NG: MamorAI cannot write $B/requests (mount /app/host-bridge, owner)"; ok=1; fi
  return $ok
}

apply() {
  local ids; ids=$(container_ids)
  install -d -m 755 /var/lib/mamorai "$B"
  install -d -m 700 -o "${ids%%:*}" -g "${ids##*:}" "$B/requests"
  install -d -m 755 "$B/results"
  cat > "$BIN" <<EOF
#!/usr/bin/env bash
# MamorAI host bridge (installer/modules/62-host-bridge.sh). Fixed tasks only; requests are removed at once.
set -uo pipefail
B=$B
DIR=$DIR
EOF
  cat >> "$BIN" <<'EOF'
audit() { logger -t mamorai-host-bridge -- "$*"; }
result() { # result <task> <ok:true|false> <ip> <message>
  python3 - "$B/results/$1.json" "$2" "$3" "$4" <<'PY'
import json,sys,datetime,os
f,ok,ip,msg=sys.argv[1:5]
tmp=f+".tmp"
json.dump({"ok":ok=="true","ip":ip or None,"error":None if ok=="true" else msg,"message":msg,"at":datetime.datetime.now(datetime.timezone.utc).isoformat()},open(tmp,"w"),ensure_ascii=False)
os.chmod(tmp,0o644); os.replace(tmp,f)
PY
}
shopt -s nullglob
for f in "$B"/requests/*.json; do
  task=$(basename "$f" .json)
  w=$(mktemp -d /run/mamorai-bridge.XXXXXX); chmod 700 "$w"
  mv -f "$f" "$w/req.json" 2>/dev/null || { rm -rf "$w"; continue; }
  chown root:root "$w/req.json"; chmod 600 "$w/req.json"
  case "$task" in
    tailscale-join)
      audit "task=tailscale-join start"
      exp=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); k=d.get("key",""); open(sys.argv[2],"w").write(k); print(d.get("expires") or "")' "$w/req.json" "$w/key" 2>/dev/null) || exp=""
      chmod 600 "$w/key" 2>/dev/null || true
      if [[ ! -s "$w/key" ]]; then result tailscale-join false "" "要求にキーが入っていません"; audit "task=tailscale-join result=NG reason=no-key"
      else
        out=$(MAMORAI_DIR="$DIR" TS_AUTHKEY_FILE="$w/key" TS_AUTHKEY_FILE_DELETE=1 TS_SKIP_STORE=1 ${exp:+TS_EXPIRES="$exp"} bash "$DIR/installer/modules/60-tailscale.sh" apply 2>&1); rc=$?
        ip=$(tailscale ip -4 2>/dev/null | head -1 || true)
        msg=$(printf '%s\n' "$out" | grep -E 'NG:|joined|already|address' | sed -E 's/tskey-[A-Za-z0-9_-]+/tskey-****/g' | tail -3 | tr '\n' ' ')
        if [[ -n "$ip" ]] && tailscale status >/dev/null 2>&1; then result tailscale-join true "$ip" "${msg:-tailnet に参加しました}"; audit "task=tailscale-join result=OK ip=$ip rc=$rc"
        else result tailscale-join false "" "${msg:-tailscale up に失敗しました}"; audit "task=tailscale-join result=NG rc=$rc"; fi
      fi;;
    pack-publish)  # EDR-171: sign the Windows pack (no secrets) and put it into the Wazuh shared folder
      out=$(bash "$DIR/installer/windows/publish-pack.sh" "$w/req.json" 2>&1); rc=$?
      msg=$(printf '%s\n' "$out" | tail -2 | tr '\n' ' ')
      if [[ $rc -eq 0 ]]; then result pack-publish true "" "$msg"; audit "task=pack-publish result=OK $msg"
      else result pack-publish false "" "$msg"; audit "task=pack-publish result=NG rc=$rc $msg"; fi;;
    *) result "$task" false "" "未対応の要求です: $task"; audit "task=$task result=NG reason=unknown";;
  esac
  rm -rf "$w"
done
EOF
  chmod 750 "$BIN"
  cat > "$UNIT.path" <<EOF
[Unit]
Description=MamorAI host bridge: watch for requests from MamorAI

[Path]
PathExistsGlob=$B/requests/*.json
MakeDirectory=no

[Install]
WantedBy=multi-user.target
EOF
  cat > "$UNIT.service" <<EOF
[Unit]
Description=MamorAI host bridge: run a fixed task requested by MamorAI
After=network-online.target docker.service

[Service]
Type=oneshot
ExecStart=$BIN
TimeoutStartSec=300
EOF
  systemctl daemon-reload
  systemctl enable --now mamorai-host-bridge.path >/dev/null 2>&1
  log "installed: $BIN, mamorai-host-bridge.path/.service, $B (requests owned by the container user $ids)"
  verify
}

revert() {
  systemctl disable --now mamorai-host-bridge.path >/dev/null 2>&1 || true
  rm -f "$UNIT.path" "$UNIT.service" "$BIN"; systemctl daemon-reload
  rm -rf "$B/requests"/* 2>/dev/null || true
  log "reverted: MamorAI can no longer ask the host for tasks (the directory $B is kept)"
}

case "$ACTION" in apply) apply ;; verify) verify ;; revert) revert ;; *) echo "usage: $0 apply|verify|revert"; exit 2 ;; esac
