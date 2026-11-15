#!/usr/bin/env bash
# MamorAI installer module 40: Wazuh watches its own configuration and MamorAI's files (EDR-90)
#   syscheck (realtime) on detection rules/decoders, manager config, dashboard/indexer security config and the
#   MamorAI installation; rules 100730-100733 alert. Catches "silence the detection with an exclusion rule" and
#   tampering outside MamorAI. Secrets (.env) are watched without content diffs.
#   usage: 40-self-monitoring.sh apply|verify|revert
set -euo pipefail
ACTION="${1:-verify}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OSSEC=/var/ossec
APP_DIR="${MAMORAI_APP_DIR:-/opt/edr-console}"
MARK_B="<!-- MamorAI self-monitoring (installer module 40) BEGIN -->"
MARK_E="<!-- MamorAI self-monitoring (installer module 40) END -->"
log() { echo "[40-self-monitoring] $*"; }
verify() {
  local ok=0
  grep -q "installer module 40) BEGIN" $OSSEC/etc/ossec.conf && log "OK: syscheck block present" || { log "NG: syscheck block missing"; ok=1; }
  cmp -s "$HERE/wazuh/rules/mamorai_selfmon_rules.xml" "$OSSEC/etc/rules/mamorai_selfmon_rules.xml" && log "OK: rules current" || { log "NG: rules missing/different"; ok=1; }
  return $ok
}
apply() {
  local bk="$OSSEC/etc/ossec.conf.bak-mamorai40-$(date +%Y%m%d%H%M%S)"; cp -p $OSSEC/etc/ossec.conf "$bk"
  python3 - $OSSEC/etc/ossec.conf "$APP_DIR" "$MARK_B" "$MARK_E" <<'PY'
import sys, re
p, app, mb, me = sys.argv[1:5]; s = open(p).read()
s = re.sub(re.escape(mb) + r".*?" + re.escape(me) + r"\n?", "", s, flags=re.S)
blk = f"""    {mb}
    <directories realtime="yes" report_changes="yes" check_all="yes">/var/ossec/etc/rules,/var/ossec/etc/decoders,/var/ossec/etc/shared</directories>
    <directories realtime="yes" check_all="yes">/var/ossec/etc/ossec.conf,/var/ossec/etc/local_internal_options.conf</directories>
    <directories realtime="yes" check_all="yes">/etc/wazuh-dashboard,/etc/wazuh-indexer/opensearch-security</directories>
    <directories realtime="yes" check_all="yes">{app}</directories>
    <ignore type="sregex">^/var/ossec/etc/(rules|decoders)/.*\\.(bak|backup|prev)</ignore>
    <ignore type="sregex">^/var/ossec/etc/ossec\\.conf\\.bak</ignore>
    {me}
"""
i = s.find("<syscheck>")
if i < 0: sys.exit("no <syscheck> block")
j = s.find("\n", i) + 1
s = s[:j] + blk + s[j:]
open(p, "w").write(s)
PY
  install -o wazuh -g wazuh -m 660 "$HERE/wazuh/rules/mamorai_selfmon_rules.xml" $OSSEC/etc/rules/mamorai_selfmon_rules.xml
  if ! $OSSEC/bin/wazuh-analysisd -t >/tmp/mamorai-analysisd.log 2>&1; then tail -5 /tmp/mamorai-analysisd.log; cp -p "$bk" $OSSEC/etc/ossec.conf; rm -f $OSSEC/etc/rules/mamorai_selfmon_rules.xml; log "validation failed, restored"; exit 1; fi
  systemctl restart wazuh-manager
  log "applied (backup $bk)"
  verify
}
revert() {
  python3 - $OSSEC/etc/ossec.conf "$MARK_B" "$MARK_E" <<'PY'
import sys, re
p, mb, me = sys.argv[1:4]; s = open(p).read()
open(p, "w").write(re.sub(r"[ \t]*" + re.escape(mb) + r".*?" + re.escape(me) + r"\n?", "", s, flags=re.S))
PY
  rm -f $OSSEC/etc/rules/mamorai_selfmon_rules.xml
  $OSSEC/bin/wazuh-analysisd -t && systemctl restart wazuh-manager && log "reverted"
}
case "$ACTION" in apply) apply ;; verify) verify ;; revert) revert ;; *) echo "usage: $0 apply|verify|revert"; exit 2 ;; esac
