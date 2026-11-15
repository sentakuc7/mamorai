#!/usr/bin/env bash
# MamorAI installer module 20: Wazuh reads MamorAI's own audit log (EDR-89/90)
#   MamorAI logs to journald with the identifier "mamorai" (docker-compose logging driver); Wazuh's journald
#   localfile picks it up, the "mamorai" decoder parses the JSON and rules 1007xx alert on sign-in failures,
#   privilege changes, runaway changes, the kill switch ...
#   usage: 20-mamorai-wazuh-ingest.sh apply|verify
set -euo pipefail
ACTION="${1:-verify}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OSSEC=/var/ossec
log() { echo "[20-wazuh-ingest] $*"; }
verify() {
  local ok=0
  grep -q "<location>journald</location>" $OSSEC/etc/ossec.conf && log "OK: journald localfile" || { log "NG: no journald localfile in ossec.conf"; ok=1; }
  for f in decoders/mamorai_decoders.xml rules/mamorai_rules.xml rules/mamorai_ar_rules.xml; do cmp -s "$HERE/wazuh/$f" "$OSSEC/etc/$f" && log "OK: $f is current" || { log "NG: $f differs or is missing"; ok=1; }; done
  journalctl -t mamorai --since -1h -q -n 1 >/dev/null 2>&1 && log "OK: MamorAI logs reach the journal" || log "WARN: no MamorAI journal lines in the last hour"
  return $ok
}
apply() {
  local changed=0
  for f in decoders/mamorai_decoders.xml rules/mamorai_rules.xml rules/mamorai_ar_rules.xml; do
    if ! cmp -s "$HERE/wazuh/$f" "$OSSEC/etc/$f"; then
      [[ -f "$OSSEC/etc/$f" ]] && cp -p "$OSSEC/etc/$f" "$OSSEC/etc/$f.prev"
      install -o wazuh -g wazuh -m 660 "$HERE/wazuh/$f" "$OSSEC/etc/$f"; changed=1
    fi
  done
  if ! grep -q "<location>journald</location>" $OSSEC/etc/ossec.conf; then
    python3 - $OSSEC/etc/ossec.conf <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
blk="\n  <!-- MamorAI audit log (installer module 20) -->\n  <localfile>\n    <log_format>journald</log_format>\n    <location>journald</location>\n  </localfile>\n"
i=s.rfind("</ossec_config>"); s=s[:i]+blk+s[i:]; open(p,"w").write(s)
PY
    changed=1
  fi
  if [[ $changed == 1 ]]; then
    if ! $OSSEC/bin/wazuh-analysisd -t >/tmp/mamorai-analysisd.log 2>&1; then
      tail -5 /tmp/mamorai-analysisd.log; for f in decoders/mamorai_decoders.xml rules/mamorai_rules.xml rules/mamorai_ar_rules.xml; do [[ -f "$OSSEC/etc/$f.prev" ]] && mv "$OSSEC/etc/$f.prev" "$OSSEC/etc/$f"; done; log "validation failed, restored"; exit 1
    fi
    rm -f $OSSEC/etc/decoders/mamorai_decoders.xml.prev $OSSEC/etc/rules/mamorai_rules.xml.prev $OSSEC/etc/rules/mamorai_ar_rules.xml.prev
    systemctl restart wazuh-manager; log "applied, manager restarted"
  else log "already up to date"; fi
  verify
}
case "$ACTION" in apply) apply ;; verify) verify ;; *) echo "usage: $0 apply|verify"; exit 2 ;; esac
