#!/usr/bin/env bash
# MamorAI installer module 15 (EDR-157): Wazuh indexer tuning for a single-node (all-in-one) server.
#   Why: with the default 1 GB heap, 3 shards per daily index and replicas that can never be placed on one node,
#   the indexer runs out of heap and refuses searches (429 circuit_breaking_exception). MamorAI then could not show
#   alerts ("internal error" before EDR-157). This module sets:
#     1. heap (-Xms/-Xmx in /etc/wazuh-indexer/jvm.options): about 30 % of RAM, 1–4 GB (INDEXER_HEAP_GB overrides)
#     2. new wazuh-alerts / wazuh-archives daily indices: 1 shard, 0 replicas (template "mamorai-wazuh-shards",
#        order 10, so it wins over the Wazuh template and survives Filebeat re-installing that template)
#     3. ISM history: 0 replicas, kept 7 days; existing .opendistro-* indices to 0 replicas (cluster becomes green)
#     4. retention (ISM): alerts ALERTS_RETENTION_DAYS (90), archives ARCHIVES_RETENTION_DAYS (7)
#   Talks to the indexer with the admin certificate in /etc/wazuh-indexer/certs (no password needed or shown).
#
#   usage: 15-indexer-tuning.sh apply|verify|revert
#   env:   INDEXER_HEAP_GB=2  ALERTS_RETENTION_DAYS=90  ARCHIVES_RETENTION_DAYS=7  NO_RESTART=1 (apply heap at next restart)
set -euo pipefail
ACTION="${1:-verify}"
JVM=/etc/wazuh-indexer/jvm.options
CERTS=/etc/wazuh-indexer/certs
URL=https://127.0.0.1:9200
ALERTS_DAYS="${ALERTS_RETENTION_DAYS:-90}"
ARCH_DAYS="${ARCHIVES_RETENTION_DAYS:-7}"
log() { echo "[15-indexer-tuning] $*"; }
[[ $(id -u) -eq 0 ]] || { log "NG: run as root"; exit 1; }

es() { # es METHOD PATH [JSON]
  curl -s --max-time 30 --cacert "$CERTS/root-ca.pem" --cert "$CERTS/admin.pem" --key "$CERTS/admin-key.pem" \
    -H 'Content-Type: application/json' -X "$1" "$URL$2" ${3:+-d "$3"}
}
want_heap() {
  if [[ -n "${INDEXER_HEAP_GB:-}" ]]; then echo "$INDEXER_HEAP_GB"; return; fi
  local mem_gb; mem_gb=$(awk '/MemTotal/{print $2/1024/1024}' /proc/meminfo)
  python3 -c "import sys; m=float(sys.argv[1]); print(max(1, min(4, int(m*0.3+0.5))))" "$mem_gb"
}
cur_heap() { awk '/^-Xmx/{print $1}' "$JVM" | head -1; }
wait_up() {
  local i; for i in $(seq 1 45); do es GET /_cluster/health | grep -q '"status"' && return 0; sleep 4; done; return 1
}
policy() { # policy <id> <days> <pattern-json> <priority>
  cat <<EOF
{"policy":{"description":"MamorAI (installer module 15): delete after $2 days","default_state":"hot",
 "states":[{"name":"hot","actions":[],"transitions":[{"state_name":"delete","conditions":{"min_index_age":"$2d"}}]},
           {"name":"delete","actions":[{"retry":{"count":3,"backoff":"exponential","delay":"1m"},"delete":{}}],"transitions":[]}],
 "ism_template":[{"index_patterns":$3,"priority":$4}]}}
EOF
}
put_policy() { # create or update an ISM policy
  local id=$1 body=$2 cur seq pt
  cur=$(es GET "/_plugins/_ism/policies/$id")
  if echo "$cur" | grep -q '"_seq_no"'; then
    seq=$(echo "$cur" | python3 -c 'import json,sys; print(json.load(sys.stdin)["_seq_no"])')
    pt=$(echo "$cur" | python3 -c 'import json,sys; print(json.load(sys.stdin)["_primary_term"])')
    es PUT "/_plugins/_ism/policies/$id?if_seq_no=$seq&if_primary_term=$pt" "$body" >/dev/null
  else
    es PUT "/_plugins/_ism/policies/$id" "$body" >/dev/null
  fi
}

verify() {
  local ok=0 h w s
  w="-Xmx$(want_heap)g"; h=$(cur_heap)
  if [[ "$h" == "$w" ]] || [[ -n "${INDEXER_HEAP_GB:-}" && "$h" == "-Xmx${INDEXER_HEAP_GB}g" ]]; then log "OK: heap $h"
  else log "NG: heap ${h:-?}（推奨 $w）"; ok=1; fi
  s=$(es GET /_template/mamorai-wazuh-shards)
  echo "$s" | grep -q '"number_of_shards":"1"' && log "OK: new daily indices use 1 shard" || { log "NG: template mamorai-wazuh-shards missing"; ok=1; }
  es GET '/_cluster/settings?filter_path=persistent' | grep -q '"number_of_replicas":"0"' && log "OK: ISM history 0 replicas" || { log "NG: ISM history replicas"; ok=1; }
  for p in wazuh-retention wazuh-archives-retention; do
    es GET "/_plugins/_ism/policies/$p" | grep -q '"policy_id"' && log "OK: retention policy $p" || { log "NG: retention policy $p missing"; ok=1; }
  done
  s=$(es GET '/_cluster/health?filter_path=status' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","?"))' 2>/dev/null || echo "?")
  [[ "$s" == green ]] && log "OK: cluster $s" || { log "NG: cluster $s"; ok=1; }
  return $ok
}

apply() {
  [[ -f "$JVM" ]] || { log "NG: $JVM not found (is wazuh-indexer installed?)"; exit 1; }
  local w h; w="$(want_heap)"; h=$(cur_heap)
  if [[ "$h" != "-Xmx${w}g" ]]; then
    cp -a "$JVM" "$JVM.pre-mamorai15.$(date +%Y%m%d%H%M%S)"
    sed -i -E "s/^-Xms[0-9]+[gGmM]$/-Xms${w}g/; s/^-Xmx[0-9]+[gGmM]$/-Xmx${w}g/" "$JVM"
    log "heap: ${h:-?} → -Xmx${w}g"
    if [[ "${NO_RESTART:-}" != 1 ]]; then
      log "restarting wazuh-indexer (searches pause for about a minute; Wazuh keeps the logs and sends them after)"
      systemctl restart wazuh-indexer
    fi
  else log "heap already -Xmx${w}g"; fi
  wait_up || { log "NG: indexer did not come back"; exit 1; }
  es PUT /_template/mamorai-wazuh-shards '{"order":10,"index_patterns":["wazuh-alerts-4.x-*","wazuh-archives-4.x-*"],"settings":{"index.number_of_shards":1,"index.number_of_replicas":0}}' >/dev/null
  log "template: new wazuh-alerts / wazuh-archives indices → 1 shard, 0 replicas"
  es PUT /_cluster/settings '{"persistent":{"plugins.index_state_management.history.number_of_replicas":0,"plugins.index_state_management.history.rollover_retention_period":"7d"}}' >/dev/null
  es PUT '/.opendistro-*/_settings?expand_wildcards=all' '{"index.number_of_replicas":0}' >/dev/null || true
  log "ISM history: 0 replicas, kept 7 days"
  put_policy wazuh-retention "$(policy wazuh-retention "$ALERTS_DAYS" '["wazuh-alerts-*"]' 100)"
  put_policy wazuh-archives-retention "$(policy wazuh-archives-retention "$ARCH_DAYS" '["wazuh-archives-*"]' 200)"
  log "retention: alerts ${ALERTS_DAYS} days, archives ${ARCH_DAYS} days (new indices; existing ones keep the policy they have)"
  # The first put_policy creates .opendistro-ism-config with 1 replica (fresh install). A single node
  # can't place it, so the cluster stays yellow → set the system indices to 0 replicas again here.
  es PUT '/.opendistro-*/_settings?expand_wildcards=all' '{"index.number_of_replicas":0}' >/dev/null || true
  local i; for i in $(seq 1 30); do es GET '/_cluster/health?filter_path=status' | grep -q green && break; sleep 4; done
  verify
}

revert() {
  es DELETE /_template/mamorai-wazuh-shards >/dev/null || true
  es PUT /_cluster/settings '{"persistent":{"plugins.index_state_management.history.number_of_replicas":null,"plugins.index_state_management.history.rollover_retention_period":null}}' >/dev/null || true
  local b; b=$(ls -t "$JVM".pre-mamorai15.* 2>/dev/null | head -1 || true)
  [[ -n "$b" ]] && cp -a "$b" "$JVM" && log "heap restored from $b (takes effect at the next indexer restart)"
  log "reverted: template and ISM history settings removed (retention policies are kept)"
}

case "$ACTION" in apply) apply ;; verify) verify ;; revert) revert ;; *) echo "usage: $0 apply|verify|revert"; exit 2 ;; esac
