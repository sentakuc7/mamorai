#!/usr/bin/env bash
# =====================================================================================================================
#  MamorAI installer (EDR-91 / EDR-148)
#    One command on a fresh server: Wazuh (all-in-one) + MamorAI + the hardening modules + agent-pack settings.
#
#    sudo ./install.sh                       interactive: asks a few questions, then runs every step
#    sudo ./install.sh --config mamorai.conf unattended: answers from a file (see installer/install.conf.example)
#    sudo ./install.sh --resume              continue after a failure (finished steps are skipped)
#    sudo ./install.sh --check               only run the final checks
#    sudo ./install.sh --reinstall-mamorai   start MamorAI over (its DB, users and .env are deleted; Wazuh is kept)
#
#  Every step is idempotent: running the installer again never re-installs what is already there.
#  Secrets (passwords, API keys, the Tailscale key) are never printed and never written to the log.
#    - typed in at a hidden prompt, or read from a file you name in the config (*_FILE), which can be deleted after use
#    - stored root-only (600): /root/mamorai/secrets.env, /opt/edr-console/.env, Wazuh's own files
#  Log: /var/log/mamorai-install.log (root only)
# =====================================================================================================================
set -Eeuo pipefail
umask 027

VERSION="0.1.0"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST=/opt/edr-console
STATE_DIR=/var/lib/mamorai-install
STATE="$STATE_DIR/done"
ANS="$STATE_DIR/answers.env"          # non-secret answers, kept for --resume
SECRETS=/root/mamorai/secrets.env
LOG=/var/log/mamorai-install.log
WAZUH_FILES=/root/wazuh/wazuh-install-files
WAZUH_PWF="$WAZUH_FILES/wazuh-passwords.txt"

# ---------------------------------------------------------------- output -------------------------------------------
if [[ -t 1 ]]; then C0=$'\e[0m'; CB=$'\e[1m'; CG=$'\e[32m'; CY=$'\e[33m'; CR=$'\e[31m'; CC=$'\e[36m'; else C0='' CB='' CG='' CY='' CR='' CC=''; fi
ts() { date '+%F %T'; }
log()  { printf '%s %s\n' "$(ts)" "$*" >>"$LOG"; }
say()  { printf '%s\n' "$*"; log "$*"; }
info() { printf '  %s\n' "$*"; log "  $*"; }
ok()   { printf '  %s✔%s %s\n' "$CG" "$C0" "$*"; log "  OK $*"; }
warn() { printf '  %s!%s %s\n' "$CY" "$C0" "$*"; log "  WARN $*"; }
die()  { CUR_STEP=""; printf '\n%s✘ %s%s\n' "$CR" "$*" "$C0" >&2; log "FAIL $*"; printf '  ログ: %s\n  直したら %ssudo ./install.sh --resume%s で続きから実行できます。\n' "$LOG" "$CB" "$C0" >&2; exit 1; }
step() { CUR_STEP="$1"; printf '\n%s==> [%s/%s] %s%s\n' "$CC$CB" "$2" "$TOTAL" "$3" "$C0"; log "=== step $1: $3"; }
trap 'rc=$?; [[ $rc -ne 0 && -n "${CUR_STEP:-}" ]] && { printf "\n%s✘ ステップ「%s」で止まりました（終了コード %s）%s\n" "$CR" "$CUR_STEP" "$rc" "$C0" >&2; log "FAIL step $CUR_STEP rc=$rc line=$LINENO"; printf "  ログ: %s\n  直したら sudo ./install.sh --resume で続きから実行できます。\n" "$LOG" >&2; }' EXIT
# mask anything that looks like a secret in third-party output before it reaches the screen or the log
mask() { sed -u -E "s/((password|passwd|passphrase|secret|token|api[_-]?key|auth[_-]?key)['\"]?[[:space:]]*[:=][[:space:]]*)['\"]?[^[:space:]'\",}]+['\"]?/\1********/Ig; s/tskey-[A-Za-z0-9_-]+/tskey-********/g; s/sk-or-[A-Za-z0-9_-]+/sk-or-********/g"; }
run_logged() { "$@" 2>&1 | mask | tee -a "$LOG"; return "${PIPESTATUS[0]}"; }

done_step() { grep -qx "$1" "$STATE" 2>/dev/null; }
mark_done() { done_step "$1" || echo "$1" >>"$STATE"; }

# ---------------------------------------------------------------- args --------------------------------------------
CONFIG=""; RESUME=0; CHECK_ONLY=0; ASSUME_YES=0; REINSTALL_APP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG="${2:-}"; shift 2;;
    --resume) RESUME=1; shift;;
    --check)  CHECK_ONLY=1; shift;;
    --reinstall-mamorai) REINSTALL_APP=1; RESUME=1; shift;;
    --yes|-y) ASSUME_YES=1; shift;;
    -h|--help) sed -n '2,16p' "$0"; exit 0;;
    *) echo "unknown option: $1 (--help)"; exit 2;;
  esac
done

[[ $(id -u) -eq 0 ]] || { echo "root で実行してください: sudo ./install.sh"; exit 1; }
mkdir -p "$STATE_DIR" /root/mamorai; chmod 700 "$STATE_DIR" /root/mamorai
touch "$LOG"; chmod 600 "$LOG"
log "----- MamorAI installer $VERSION start (src $SRC) -----"

# ---------------------------------------------------------------- answers -----------------------------------------
# config file: KEY=VALUE lines (no shell evaluation)
declare -A CFG=()
load_kv() { local f="$1" k v; [[ -f "$f" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"; [[ "$line" =~ ^[[:space:]]*([A-Z_][A-Z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"; v="${v%"${v##*[![:space:]]}"}"; v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"; CFG[$k]="$v"
  done <"$f"; }
[[ $RESUME -eq 1 || $CHECK_ONLY -eq 1 ]] && load_kv "$ANS"
[[ -n "$CONFIG" ]] && { [[ -f "$CONFIG" ]] || { echo "config not found: $CONFIG"; exit 1; }; load_kv "$CONFIG"; ASSUME_YES=1; }
INTERACTIVE=0; [[ -t 0 && $ASSUME_YES -eq 0 ]] && INTERACTIVE=1

ask() { # ask KEY "question" default [regex]
  local key="$1" q="$2" def="${3:-}" re="${4:-.*}" a
  if [[ -n "${CFG[$key]:-}" ]]; then return; fi
  if [[ $INTERACTIVE -eq 0 ]]; then CFG[$key]="$def"; return; fi
  while :; do read -r -p "  $q${def:+ [$def]}: " a; a="${a:-$def}"; [[ "$a" =~ ^($re)$ ]] && break; echo "    → 入力の形が違います"; done
  CFG[$key]="$a"
}
yesno() { local key="$1" q="$2" def="$3"; ask "$key" "$q (y/n)" "$def" "[yYnN]|yes|no"; case "${CFG[$key]}" in [yY]*) CFG[$key]=yes;; *) CFG[$key]=no;; esac; }
ask_secret() { # ask_secret VAR "prompt" [file-key]  → value in the named variable, never echoed
  local __v="$1" q="$2" fk="${3:-}" s=""
  if [[ -n "$fk" && -n "${CFG[$fk]:-}" ]]; then [[ -r "${CFG[$fk]}" ]] || die "$fk のファイルが読めません"; s="$(head -1 "${CFG[$fk]}" | tr -d '\r\n')"
  elif [[ $INTERACTIVE -eq 1 ]]; then read -r -s -p "  $q（入力は表示されません）: " s; echo
  fi
  printf -v "$__v" '%s' "$s"
}
save_answers() { : >"$ANS"; chmod 600 "$ANS"; for k in "${!CFG[@]}"; do [[ "$k" == *_FILE ]] && continue; printf '%s=%s\n' "$k" "${CFG[$k]}" >>"$ANS"; done; }

detect_lan() { { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'; } || true; }
detect_cidr() { local a; a=$(detect_lan); ip -4 -o addr show 2>/dev/null | awk -v a="$a" '$4 ~ "^"a"/" {print $4; exit}' | python3 -c "import ipaddress,sys; s=sys.stdin.read().strip(); print(ipaddress.ip_interface(s).network if s else '')" 2>/dev/null || true; }

gather() {
  say ""
  say "${CB}MamorAI のインストール${C0}  — Wazuh と MamorAI をこのサーバーに入れます"
  [[ $INTERACTIVE -eq 1 ]] && say "  わからないところは Enter で [ ] の値になります。"
  local lan; lan="$(detect_lan)"
  ask ADMIN_EMAIL   "管理者のメールアドレス（MamorAI のログイン ID）" "admin@example.com" "[^@[:space:]]+@[^@[:space:]]+"
  ask SERVER_NAME   "このサーバーの名前（Wazuh / MamorAI の画面に出ます）" "$(hostname -s)" "[A-Za-z0-9._-]+"
  ask LAN_ADDR      "このサーバーの LAN アドレス（端末がつなぐ先）" "${lan:-}" "[0-9.]+"
  ask LAN_CIDR      "LAN の範囲（ファイアウォールで許可する範囲）" "$(detect_cidr)" "[0-9./]+"
  ask CONNECT       "端末のつなぎ方: lan / tailscale / public" "lan" "lan|tailscale|public"
  [[ "${CFG[CONNECT]}" == public ]] && ask PUBLIC_ADDR "公開アドレス（DNS 名か IP）" "" ".+"
  ask LLM_PROVIDER  "AI: openrouter / anthropic / ollama / none（あとで設定画面からも変えられます）" "openrouter" "openrouter|anthropic|ollama|none"
  [[ "${CFG[LLM_PROVIDER]}" == ollama ]] && ask OLLAMA_URL "Ollama の URL" "http://127.0.0.1:11434" "https?://.+"
  yesno WINDOWS_ADDON "Windows 端末の遮断操作用アドオン（署名つき）を作りますか" y
  yesno UFW           "ファイアウォール（ufw）を有効にして、LAN と SSH だけ許可しますか" n
  ask WAZUH_VERSION "Wazuh の版（メジャー.マイナー）" "4.14" "[0-9]+\.[0-9]+"
  ask_admin_password
  save_answers
}

# MamorAI の管理画面にログインする管理者パスワード: このウィザードで決める（12 文字以上、2 回入力）。表示もログも残さない
ADMIN_PW_INPUT=""
ask_admin_password() {
  if [[ -s "$SECRETS" ]] && grep -q '^APP_ADMIN_PASSWORD=.' "$SECRETS"; then return; fi
  if [[ -n "${CFG[ADMIN_PASSWORD_FILE]:-}" ]]; then ask_secret ADMIN_PW_INPUT "" ADMIN_PASSWORD_FILE; [[ ${#ADMIN_PW_INPUT} -ge 12 ]] || die "ADMIN_PASSWORD_FILE のパスワードが 12 文字未満です"; return; fi
  [[ $INTERACTIVE -eq 1 ]] || die "無人実行では ADMIN_PASSWORD_FILE（管理者パスワードを書いた root だけが読めるファイル）を指定してください"
  local a b
  say ""; say "  ${CB}MamorAI の管理画面にログインするパスワードを決めてください${C0}（ログイン ID: ${CFG[ADMIN_EMAIL]}）"
  while :; do
    read -r -s -p "  管理者パスワード（12 文字以上。入力は表示されません）: " a; echo
    [[ ${#a} -ge 12 ]] || { echo "    → 12 文字以上にしてください"; continue; }
    [[ "$a" != *"'"* && "$a" != *$'\n'* ]] || { echo "    → ' （シングルクォート）は使えません"; continue; }
    read -r -s -p "  もう一度入力してください: " b; echo
    [[ "$a" == "$b" ]] && { ADMIN_PW_INPUT="$a"; a=""; b=""; ok "管理者パスワードを受け取りました（表示しません）"; return; }
    echo "    → 1 回目と違います。もう一度入力してください"
  done
}

summary_of_answers() {
  say ""; say "${CB}この内容で進めます${C0}"
  info "管理者: ${CFG[ADMIN_EMAIL]} / サーバー名: ${CFG[SERVER_NAME]} / LAN: ${CFG[LAN_ADDR]} (${CFG[LAN_CIDR]})"
  info "つなぎ方: ${CFG[CONNECT]}${CFG[PUBLIC_ADDR]:+ (${CFG[PUBLIC_ADDR]})} / AI: ${CFG[LLM_PROVIDER]} / Windows アドオン: ${CFG[WINDOWS_ADDON]} / ufw: ${CFG[UFW]} / Wazuh ${CFG[WAZUH_VERSION]}"
  if [[ $INTERACTIVE -eq 1 ]]; then local a; read -r -p "  よろしいですか？ (y/n) [y]: " a; [[ "${a:-y}" =~ ^[yY] ]] || { say "中止しました（何も変更していません）"; exit 2; }; fi
}

# ---------------------------------------------------------------- helpers -----------------------------------------
os_id() { . /etc/os-release; echo "${ID}:${VERSION_ID}"; }
pkg_install() {
  if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive run_logged apt-get install -y -q "$@" >/dev/null
  else run_logged dnf install -y -q "$@" >/dev/null; fi
}
gen_pw() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Ma'+''.join(secrets.choice(a) for _ in range(26))+'7_.x')"; }
pw_of() { # pw_of indexer|api user   (reads wazuh-passwords.txt, prints to stdout for capture only)
  local kind="$1" user="$2"
  awk -v k="${kind}_username" -v u="$user" '$0 ~ k": *.?"u".?$" {getline; sub(/.*_password: */,""); gsub(/\x27|"/,""); print; exit}' "$WAZUH_PWF"
}
env_set() { # env_set FILE KEY VALUE  (value never echoed)
  python3 - "$1" "$2" "$3" <<'PY'
import sys,re
f,k,v=sys.argv[1:4]
# values with special characters are single-quoted (docker compose env_file: no ${} interpolation, no inline comments)
if len(v)>=2 and v[0]==v[-1]=="'": v=v[1:-1]
if not re.fullmatch(r"[A-Za-z0-9._@:/+=-]*", v): v="'"+v+"'"
s=open(f).read().rstrip('\n').split('\n')
out=[];found=False
for l in s:
    if re.match(r'^'+re.escape(k)+r'=',l): out.append(f'{k}={v}'); found=True
    else: out.append(l)
if not found: out.append(f'{k}={v}')
open(f,'w').write('\n'.join(out).rstrip('\n')+'\n')
PY
}
mamorai_up() { (cd "$DEST" && docker compose ps --status running --services 2>/dev/null | grep -qx edr-console); }
wait_mamorai() {
  local i
  for i in $(seq 1 90); do curl -sk --max-time 3 https://127.0.0.1:8444/api/health 2>/dev/null | grep -q '"ok":true' && return 0; sleep 2; done
  return 1
}
cli() { (cd "$DEST" && docker compose exec -T edr-console node server/dist/cli.js "$@"); }
dash_port() { local p; p=$(awk -F': *' '/^server.port:/{print $2}' /etc/wazuh-dashboard/opensearch_dashboards.yml 2>/dev/null | tr -d '"\r '); echo "${p:-443}"; }

# ---------------------------------------------------------------- steps -------------------------------------------
s_preflight() {
  local id cpu mem disk
  id="$(os_id)"; cpu=$(nproc); mem=$(awk '/MemTotal/{print int($2/1024/1024+0.5)}' /proc/meminfo); disk=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
  case "$id" in ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|rocky:9*|almalinux:9*|rhel:9*) ok "OS: $id";; *) warn "OS $id は未検証です（Ubuntu 22.04 / 24.04 / 26.04、RHEL 9 系を推奨）";; esac
  [[ $cpu -ge 4 ]] && ok "CPU: $cpu コア" || warn "CPU が $cpu コアです（4 以上を推奨）"
  [[ $mem -ge 8 ]] && ok "メモリ: ${mem} GB" || { [[ $mem -ge 4 ]] && warn "メモリが ${mem} GB です（8 GB 以上を推奨。Wazuh の動作が重くなります）" || die "メモリが ${mem} GB です。Wazuh には最低 4 GB 必要です"; }
  [[ $disk -ge 50 ]] && ok "空きディスク: ${disk} GB" || warn "空きディスクが ${disk} GB です（100 GB 以上を推奨）"
  local p
  for p in 1514 1515 9200 55000 443 8444; do
    ss -ltnH "sport = :$p" 2>/dev/null | grep -q . || continue
    if [[ $p == 8444 ]]; then mamorai_up 2>/dev/null || warn "ポート 8444 は別のプロセスが使っています（MamorAI が使います）"
    else systemctl is-active -q wazuh-manager 2>/dev/null || systemctl is-active -q wazuh-indexer 2>/dev/null || warn "ポート $p は別のプロセスが使っています（Wazuh が使います）"; fi
  done
  command -v curl >/dev/null || pkg_install curl
  command -v python3 >/dev/null || pkg_install python3
  local code; code=$(curl -s --max-time 15 -o /dev/null -w '%{http_code}' "https://packages.wazuh.com/${CFG[WAZUH_VERSION]}/wazuh-install.sh" || true)
  [[ "$code" == 200 ]] && ok "Wazuh の配布元に届きます（packages.wazuh.com/${CFG[WAZUH_VERSION]}）" || die "Wazuh のインストーラーを取得できません（HTTP ${code:-接続不可}。プロキシ / DNS / 版 WAZUH_VERSION を確認）"
  code=$(curl -s --max-time 15 -o /dev/null -w '%{http_code}' https://registry-1.docker.io/v2/ || true)
  [[ "$code" =~ ^(200|401)$ ]] && ok "Docker Hub に届きます" || die "Docker Hub（registry-1.docker.io）に届きません（HTTP ${code:-接続不可}）"
}

s_wazuh() {
  if systemctl is-active -q wazuh-manager 2>/dev/null && systemctl is-active -q wazuh-indexer 2>/dev/null; then
    ok "Wazuh はすでに入っています（$(/var/ossec/bin/wazuh-control info -v 2>/dev/null || echo '?')）。入れ直しはしません"
  else
    local v="${CFG[WAZUH_VERSION]}" work=/root/wazuh/install
    mkdir -p "$work"; cd "$work"
    info "Wazuh $v の公式インストーラーを取得します"
    curl -sSfO "https://packages.wazuh.com/$v/wazuh-install.sh" || die "https://packages.wazuh.com/$v/wazuh-install.sh を取得できません（版を確認: WAZUH_VERSION）"
    info "Wazuh を all-in-one で入れます（15〜30 分かかります。進み具合は下に出ます）"
    local extra=(); [[ $(nproc) -lt 2 || $(awk '/MemTotal/{print int($2/1024/1024+0.5)}' /proc/meminfo) -lt 4 ]] && extra=(-i)
    run_logged bash ./wazuh-install.sh -a "${extra[@]}" || die "Wazuh のインストールに失敗しました（/var/log/wazuh-install.log も確認してください）"
    cd /
  fi
  if [[ ! -f "$WAZUH_PWF" ]]; then
    local tarf; tarf="$(ls -t /root/wazuh/install/wazuh-install-files.tar /root/wazuh-install-files.tar ./wazuh-install-files.tar 2>/dev/null | head -1 || true)"
    [[ -n "$tarf" ]] || die "wazuh-install-files.tar が見つかりません（Wazuh の管理者パスワードの入ったファイル）"
    tar -xf "$tarf" -C /root/wazuh; chmod -R go-rwx /root/wazuh
  fi
  [[ -s "$WAZUH_PWF" ]] && ok "Wazuh のパスワードファイル: $WAZUH_PWF（root だけが読めます。中身は表示しません）"
  local svc; for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do systemctl is-active -q "$svc" && ok "$svc: active" || die "$svc が動いていません"; done
}

s_ro_users() {
  if [[ -s "$SECRETS" ]] && grep -q '^WAZUH_INDEXER_PASSWORD=.' "$SECRETS" && grep -q '^WAZUH_API_PASSWORD=.' "$SECRETS"; then
    local ip ap; ip=$(grep '^WAZUH_INDEXER_PASSWORD=' "$SECRETS" | cut -d= -f2-); ap=$(grep '^WAZUH_API_PASSWORD=' "$SECRETS" | cut -d= -f2-)
    if curl -sk -o /dev/null -w '%{http_code}' -u "edr-console-ro:$ip" https://127.0.0.1:9200/ | grep -q 200 && curl -sk -u "edr-console-ro:$ap" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true" | grep -q '\.'; then
      ok "読み取り専用ユーザー（edr-console-ro）は作成済みです"; ensure_app_secrets; return
    fi
    warn "保存してある読み取り専用ユーザーで入れません。作り直します"
  fi
  local ADMIN_PW API_PW RO_IDX RO_API T UID_ RID code
  ADMIN_PW="$(pw_of indexer admin)"; API_PW="$(pw_of api wazuh)"
  [[ -n "$ADMIN_PW" && -n "$API_PW" ]] || die "wazuh-passwords.txt から admin / wazuh のパスワードを読めません"
  RO_IDX="$(gen_pw)"; RO_API="$(gen_pw)"
  code=$(curl -sk -o /tmp/.mi.$$ -w '%{http_code}' -u "admin:$ADMIN_PW" -X PUT https://127.0.0.1:9200/_plugins/_security/api/internalusers/edr-console-ro \
    -H 'Content-Type: application/json' -d "{\"password\":\"$RO_IDX\",\"backend_roles\":[\"readall\"]}")
  rm -f /tmp/.mi.$$; [[ "$code" =~ ^20[01]$ ]] && ok "indexer: edr-console-ro（readall）" || die "indexer にユーザーを作れません（HTTP $code）"
  T=$(curl -sk -u "wazuh:$API_PW" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true"); [[ "$T" == *.*.* ]] || die "Wazuh API にログインできません"
  UID_=$(curl -sk -H "Authorization: Bearer $T" "https://127.0.0.1:55000/security/users?search=edr-console-ro" | python3 -c "import json,sys; a=[u for u in json.load(sys.stdin)['data']['affected_items'] if u['username']=='edr-console-ro']; print(a[0]['id'] if a else '')")
  if [[ -n "$UID_" ]]; then
    curl -sk -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -X PUT "https://127.0.0.1:55000/security/users/$UID_" -d "{\"password\":\"$RO_API\"}" >/dev/null
  else
    UID_=$(curl -sk -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -X POST https://127.0.0.1:55000/security/users -d "{\"username\":\"edr-console-ro\",\"password\":\"$RO_API\"}" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['affected_items'][0]['id'])") || die "Wazuh API にユーザーを作れません"
  fi
  RID=$(curl -sk -H "Authorization: Bearer $T" "https://127.0.0.1:55000/security/roles?search=readonly" | python3 -c "import json,sys; print(next(r['id'] for r in json.load(sys.stdin)['data']['affected_items'] if r['name']=='readonly'))")
  curl -sk -H "Authorization: Bearer $T" -X POST "https://127.0.0.1:55000/security/users/$UID_/roles?role_ids=$RID" >/dev/null
  ok "Wazuh API: edr-console-ro（readonly）"
  touch "$SECRETS"; chmod 600 "$SECRETS"
  env_set "$SECRETS" WAZUH_INDEXER_PASSWORD "$RO_IDX"; env_set "$SECRETS" WAZUH_API_PASSWORD "$RO_API"
  ensure_app_secrets
  ok "資格情報を $SECRETS に保存しました（root だけが読めます）"
}

ensure_app_secrets() {
  touch "$SECRETS"; chmod 600 "$SECRETS"
  grep -q '^APP_SECRET=.' "$SECRETS" || env_set "$SECRETS" APP_SECRET "$(openssl rand -hex 32)"
  if ! grep -q '^APP_ADMIN_PASSWORD=.' "$SECRETS"; then
    [[ -n "$ADMIN_PW_INPUT" ]] || die "管理者パスワードが決まっていません（もう一度 sudo ./install.sh を実行してください）"
    env_set "$SECRETS" APP_ADMIN_PASSWORD "$ADMIN_PW_INPUT"; env_set "$SECRETS" APP_ADMIN_MUST_CHANGE false; ADMIN_PW_INPUT=""
    ok "管理者パスワードを保存しました（root だけが読めるファイル。表示しません）"
  fi
  chmod 600 "$SECRETS"
}

s_docker() {
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then ok "Docker: $(docker --version | cut -d, -f1)"; else
    info "Docker を入れます"
    if command -v apt-get >/dev/null; then run_logged apt-get update -q >/dev/null; pkg_install docker.io docker-compose-v2
    else pkg_install dnf-plugins-core; run_logged dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo >/dev/null; pkg_install docker-ce docker-ce-cli containerd.io docker-compose-plugin; fi
  fi
  systemctl enable --now docker >/dev/null 2>&1; docker compose version >/dev/null 2>&1 || die "docker compose が使えません"; ok "docker compose: $(docker compose version --short)"
}

s_mamorai() {
  # 1. files
  if [[ "$SRC" != "$DEST" ]]; then info "MamorAI を $DEST に配置します"; copy_app; fi
  install -d -m 755 /var/lib/mamorai /var/lib/mamorai/host-bridge
  mkdir -p "$DEST/secrets" "$DEST/addon"
  # the container runs as a non-root user: it must be able to enter secrets/ (only the public CA certificate is there)
  chmod 755 "$DEST/secrets" "$DEST/addon"
  install -m 644 /etc/wazuh-indexer/certs/root-ca.pem "$DEST/secrets/wazuh-root-ca.pem"
  # 2. .env (created once; later runs only fill in what is missing)
  local E="$DEST/.env" first=0
  if [[ ! -f "$E" ]]; then cp "$DEST/.env.example" "$E"; first=1; fi
  chmod 600 "$E"
  local k
  for k in APP_SECRET APP_ADMIN_PASSWORD APP_ADMIN_MUST_CHANGE WAZUH_INDEXER_PASSWORD WAZUH_API_PASSWORD; do
    grep -q "^$k=" "$SECRETS" || continue
    grep -q "^$k=." "$E" && [[ $first -eq 0 ]] && continue
    env_set "$E" "$k" "$(grep "^$k=" "$SECRETS" | cut -d= -f2-)"
  done
  env_set "$E" APP_BASE_URL "https://${CFG[LAN_ADDR]}:8444"
  env_set "$E" APP_ADMIN_EMAIL "${CFG[ADMIN_EMAIL]}"
  env_set "$E" WAZUH_NAME "${CFG[SERVER_NAME]}"
  # the Wazuh dashboard is reached through MamorAI (/wazuh, module 30): point MamorAI at the dashboard's real port
  env_set "$E" WAZUH_DASHBOARD_URL "https://127.0.0.1:$(dash_port)"
  # 3. AI (key typed at a hidden prompt or read from LLM_API_KEY_FILE)
  case "${CFG[LLM_PROVIDER]}" in
    openrouter|anthropic)
      local var=OPENROUTER_API_KEY; [[ "${CFG[LLM_PROVIDER]}" == anthropic ]] && var=ANTHROPIC_API_KEY
      env_set "$E" LLM_PROVIDER "${CFG[LLM_PROVIDER]}"
      if grep -q "^$var=." "$E"; then ok "AI の API キーは設定済みです"; else
        local key=""; ask_secret key "${CFG[LLM_PROVIDER]} の API キー（空なら AI なしで続けます）" LLM_API_KEY_FILE
        if [[ -n "$key" ]]; then env_set "$E" "$var" "$key"; ok "AI の API キーを保存しました（表示しません）"; else warn "AI のキーなしで続けます（あとで .env に入れて docker compose up -d）"; fi
        key=""; [[ "${CFG[LLM_API_KEY_FILE_DELETE]:-no}" == yes && -n "${CFG[LLM_API_KEY_FILE]:-}" ]] && shred -u "${CFG[LLM_API_KEY_FILE]}" 2>/dev/null || true
      fi;;
    ollama) env_set "$E" LLM_PROVIDER ollama; env_set "$E" OLLAMA_URL "${CFG[OLLAMA_URL]}";;
    none) info "AI は設定しません（あとから .env で設定できます）";;
  esac
  # 4. build and start
  info "MamorAI のイメージを作って起動します（初回は 5〜10 分かかります）"
  (cd "$DEST" && run_logged docker compose build) >/dev/null || die "MamorAI のビルドに失敗しました（ログを確認）"
  (cd "$DEST" && run_logged docker compose up -d) >/dev/null || die "MamorAI を起動できません"
  wait_mamorai && ok "MamorAI が起動しました: https://${CFG[LAN_ADDR]}:8444" || die "MamorAI が応答しません（cd $DEST && docker compose logs --tail 50）"
}

s_modules() {
  local m="$DEST/installer/modules"
  run_logged bash "$m/15-indexer-tuning.sh" apply          || die "モジュール 15（Wazuh indexer のメモリ・シャード・保存期間）が失敗しました"
  run_logged bash "$m/20-mamorai-wazuh-ingest.sh" apply   || die "モジュール 20（MamorAI の監査ログを Wazuh へ）が失敗しました"
  run_logged bash "$m/40-self-monitoring.sh" apply        || die "モジュール 40（改ざん監視）が失敗しました"
  MAMORAI_ENV="$DEST/.env" WAZUH_PASSWORDS_FILE="$WAZUH_PWF" run_logged bash "$m/50-wazuh-ar-user.sh" apply || die "モジュール 50（遮断操作用の API ユーザー）が失敗しました"
  (cd "$DEST" && run_logged docker compose up -d) >/dev/null; wait_mamorai || die "MamorAI が再起動後に応答しません"
  MAMORAI_DIR="$DEST" run_logged bash "$m/55-wazuh-enrollment-password.sh" apply || die "モジュール 55（エージェント登録パスワード）が失敗しました"
  ok "Wazuh 側の仕上げ（15 / 20 / 40 / 50 / 55）が終わりました"
}

APP_EXCLUDES=(--exclude=./.git --exclude=./node_modules --exclude=./data --exclude=./.env --exclude=./secrets --exclude=./addon)
copy_app() { mkdir -p "$DEST"; tar -C "$SRC" "${APP_EXCLUDES[@]}" -cf - . | tar -C "$DEST" -xf -; }
# a newer package was unpacked and the installer runs again (--resume): bring /opt/edr-console up to date and rebuild
sync_app() {
  [[ "$SRC" != "$DEST" && -f "$DEST/docker-compose.yml" ]] || return 0
  if diff -rq -x .git -x node_modules -x data -x .env -x secrets -x addon "$SRC" "$DEST" >/dev/null 2>&1; then return 0; fi
  info "新しい版のファイルを $DEST に反映して、MamorAI を作り直します"
  copy_app; install -d -m 755 /var/lib/mamorai /var/lib/mamorai/host-bridge
  (cd "$DEST" && run_logged docker compose build) >/dev/null || die "MamorAI のビルドに失敗しました"
  (cd "$DEST" && run_logged docker compose up -d) >/dev/null || die "MamorAI を起動できません"
  wait_mamorai || die "MamorAI が応答しません"; ok "MamorAI を新しい版にしました"
}

s_dashboard() {
  local m="$DEST/installer/modules"
  if bash "$m/30-wazuh-dashboard-frontdoor.sh" verify >/dev/null 2>&1; then ok "Wazuh ダッシュボードは MamorAI の中（/wazuh）からだけ開けます（設定済み）"; return; fi
  python3 -c 'import yaml' 2>/dev/null || pkg_install python3-yaml
  info "Wazuh ダッシュボードを 127.0.0.1 だけで待ち受けにして、MamorAI のログイン（パスワード + 認証アプリ）の後ろに置きます"
  run_logged bash "$m/30-wazuh-dashboard-frontdoor.sh" apply || die "モジュール 30（ダッシュボードを MamorAI の中へ）が失敗しました"
  local E="$DEST/.env"
  env_set "$E" WAZUH_DASHBOARD_URL "https://127.0.0.1:$(dash_port)"
  (cd "$DEST" && run_logged docker compose up -d) >/dev/null; wait_mamorai || die "MamorAI が再起動後に応答しません"
  bash "$m/30-wazuh-dashboard-frontdoor.sh" verify >/dev/null 2>&1 && ok "Wazuh ダッシュボード: MamorAI の「Wazuh ダッシュボード」から開けます（直接のアクセスは閉じました）" || die "モジュール 30 の確認（verify）が NG です"
}

s_addon() {
  if [[ "${CFG[WINDOWS_ADDON]}" != yes ]]; then info "Windows アドオンは作りません（あとで installer/windows/build-addon.sh）"; return; fi
  if ls "$DEST"/addon/*.ps1 >/dev/null 2>&1; then ok "Windows アドオンは作成済みです"; return; fi
  command -v osslsigncode >/dev/null || pkg_install osslsigncode || die "osslsigncode を入れられません"
  (cd "$DEST" && run_logged bash installer/windows/build-addon.sh --keys /root/mamorai-signing --out ./addon) >/dev/null || die "Windows アドオンの作成に失敗しました"
  chmod -R a+rX "$DEST/addon"
  ok "Windows アドオンを作りました。署名の秘密鍵 /root/mamorai-signing/signing.key は、サーバーの外にもバックアップしてください"
}

s_connect() {
  local m="$DEST/installer/modules" js
  local pub=""; [[ -n "${CFG[PUBLIC_ADDR]:-}" ]] && pub=",\"public\":\"${CFG[PUBLIC_ADDR]}\""
  js="{\"manager\":{\"lan\":\"${CFG[LAN_ADDR]}\"${pub}},\"linux\":{\"ssh\":{\"allow_from\":[\"${CFG[LAN_ADDR]}\"]}}}"
  cli agent-pack set "$js" >/dev/null 2>&1 || die "エージェントパックの設定に失敗しました"
  ok "エージェントパックの接続先: LAN ${CFG[LAN_ADDR]}${CFG[PUBLIC_ADDR]:+ / 公開 ${CFG[PUBLIC_ADDR]}}"
  sync_app
  # host bridge: lets the MamorAI screen ask the host for fixed root tasks (e.g. join the tailnet with the key entered there)
  if MAMORAI_DIR="$DEST" bash "$m/62-host-bridge.sh" verify >/dev/null 2>&1; then ok "ホスト連携（MamorAI の画面からの依頼）は設定済みです"
  else run_logged env MAMORAI_DIR="$DEST" bash "$m/62-host-bridge.sh" apply >/dev/null || die "モジュール 62（ホスト連携）が失敗しました"; ok "ホスト連携を入れました（MamorAI の画面から、Tailscale への参加などを依頼できます）"; fi
  if [[ "${CFG[CONNECT]}" == tailscale ]]; then
    if MAMORAI_DIR="$DEST" bash "$m/60-tailscale.sh" verify >/dev/null 2>&1; then ok "Tailscale は設定済みです"
    elif [[ -n "${CFG[TS_AUTHKEY_FILE]:-}" ]]; then
      # unattended: the key comes from a root-only file named in the config
      local envs=(MAMORAI_DIR="$DEST" TS_HOSTNAME="${CFG[SERVER_NAME]}" TS_AUTHKEY_FILE="${CFG[TS_AUTHKEY_FILE]}")
      [[ -n "${CFG[TS_EXPIRES]:-}" ]] && envs+=(TS_EXPIRES="${CFG[TS_EXPIRES]}")
      [[ "${CFG[TS_AUTHKEY_FILE_DELETE]:-no}" == yes ]] && envs+=(TS_AUTHKEY_FILE_DELETE=1)
      run_logged env "${envs[@]}" bash "$m/60-tailscale.sh" apply >/dev/null || die "Tailscale の設定に失敗しました"
      ok "Tailscale に参加しました（$(tailscale ip -4 2>/dev/null | head -1)）"
    else
      run_logged env MAMORAI_DIR="$DEST" bash "$m/60-tailscale.sh" prepare >/dev/null || die "Tailscale の準備に失敗しました"
      ok "Tailscale を入れました。キーは MamorAI の画面で入れます（このあとの案内を参照）"
    fi
  fi
}

s_firewall() {
  if [[ "${CFG[UFW]}" != yes ]]; then info "ファイアウォールは変更しません"; return; fi
  command -v ufw >/dev/null || pkg_install ufw
  local cidr="${CFG[LAN_CIDR]}" p
  ufw allow 22/tcp comment "ssh" >/dev/null
  for p in 1514 1515 8444; do ufw allow from "$cidr" to any port "$p" proto tcp comment "mamorai-lan" >/dev/null; done
  [[ "${CFG[CONNECT]}" == public ]] && warn "公開アドレスの場合は、クラウド側のファイアウォールで 1514/1515 を接続元に絞ってください"
  ufw --force enable >/dev/null && ok "ufw: SSH と、LAN（$cidr）からの 1514 / 1515 / 8444 を許可して有効にしました"
  if [[ "${CFG[CONNECT]}" == tailscale ]]; then for p in 1514 1515 8444 22; do ufw allow in on tailscale0 to any port "$p" proto tcp comment "mamorai-tailscale" >/dev/null; done; ok "ufw: tailscale0 で 1514 / 1515 / 8444 / 22 を許可"; fi
}

s_check() {
  local ng=0 m="$DEST/installer/modules" r
  say ""; say "${CB}確認${C0}"
  local svc; for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do systemctl is-active -q "$svc" && ok "$svc: active" || { warn "$svc: 停止"; ng=1; }; done
  mamorai_up && wait_mamorai && ok "MamorAI: 応答あり（https://${CFG[LAN_ADDR]:-$(detect_lan)}:8444）" || { warn "MamorAI: 応答なし"; ng=1; }
  r=$(curl -sk https://127.0.0.1:8444/api/health 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('version',''))" 2>/dev/null || true); [[ -n "$r" ]] && info "MamorAI version $r"
  for mod in 15-indexer-tuning 20-mamorai-wazuh-ingest 30-wazuh-dashboard-frontdoor 40-self-monitoring 55-wazuh-enrollment-password; do
    MAMORAI_DIR="$DEST" bash "$m/$mod.sh" verify >/dev/null 2>&1 && ok "module $mod" || { warn "module $mod: verify NG（sudo $m/$mod.sh verify で詳細）"; ng=1; }
  done
  MAMORAI_ENV="$DEST/.env" WAZUH_PASSWORDS_FILE="$WAZUH_PWF" bash "$m/50-wazuh-ar-user.sh" verify >/dev/null 2>&1 && ok "module 50-wazuh-ar-user" || { warn "module 50-wazuh-ar-user: verify NG"; ng=1; }
  MAMORAI_DIR="$DEST" bash "$m/62-host-bridge.sh" verify >/dev/null 2>&1 && ok "module 62-host-bridge" || { warn "module 62-host-bridge: verify NG"; ng=1; }
  if [[ "${CFG[CONNECT]:-}" == tailscale ]]; then
    if MAMORAI_DIR="$DEST" bash "$m/60-tailscale.sh" verify >/dev/null 2>&1; then ok "Tailscale: 参加済み（$(tailscale ip -4 2>/dev/null | head -1)）"
    else info "Tailscale: まだ参加していません → MamorAI の「設定 › エージェントパック › 秘密情報」でキーを入れると、このサーバーが参加します"; TS_PENDING=1; fi
  fi
  r=$(cli agent-pack show 2>/dev/null | python3 -c "
import json,sys
t=sys.stdin.read(); d=json.loads(t[t.find('{'):])
for k,v in d.get('packs',{}).items():
    print(('OK ' if not v.get('problems') else 'NG ')+f\"{k} r{v.get('rev')}\"+(' — '+' / '.join(v['problems']) if v.get('problems') else ''))" 2>/dev/null || true)
  if [[ -z "$r" ]]; then warn "エージェントパックの状態を読めません"; ng=1; else
    while IFS= read -r l; do [[ "$l" == OK* ]] && ok "エージェントパック: ${l#OK }" || { warn "エージェントパック: ${l#NG }"; ng=1; }; done <<<"$r"; fi
  case "$(grep -E '^LLM_PROVIDER=' "$DEST/.env" 2>/dev/null | cut -d= -f2 | tr -d "'\" ")" in
    openrouter) grep -qE '^OPENROUTER_API_KEY=.' "$DEST/.env" && ok "AI: OpenRouter（キー設定あり）" || warn "AI: OpenRouter のキーがありません";;
    anthropic)  grep -qE '^ANTHROPIC_API_KEY=.' "$DEST/.env" && ok "AI: Anthropic（キー設定あり）" || warn "AI: Anthropic のキーがありません";;
    ollama) ok "AI: Ollama";;
    *) info "AI: 未設定";;
  esac
  return $ng
}

finish_message() {
  say ""
  say "${CG}${CB}インストールが終わりました${C0}"
  say ""
  say "  1. ブラウザで ${CB}https://${CFG[LAN_ADDR]}:8444${C0} を開く（自己署名証明書の警告は確認して進む）"
  if grep -q '^APP_ADMIN_MUST_CHANGE=false' "$SECRETS" 2>/dev/null; then
    say "  2. ${CFG[ADMIN_EMAIL]} と、インストールのときに決めたパスワードでログインする"
    say "  3. 認証アプリで QR を読み取る（リカバリーコードは保存する）"
  else
    say "  2. ${CFG[ADMIN_EMAIL]} と初回用パスワードでログインする。初回用パスワードの確認:"
    say "       ${CB}sudo grep APP_ADMIN_PASSWORD $SECRETS${C0}"
    say "  3. パスワードを変え、認証アプリで QR を読み取る（リカバリーコードは保存する）"
  fi
  if [[ "${TS_PENDING:-0}" == 1 ]]; then
    say "  4. ${CB}「設定 › エージェントパック › 秘密情報」で Tailscale の認証キーと期限を入れて保存する${C0}"
    say "     → このサーバーが Tailscale に参加し、パックにもキーが入ります（参加の結果は同じ画面に出ます）"
    say "  5. 「管理ホスト › エージェントパック」から Windows / Linux 用のパックを DL して、端末で実行する"
  else
    say "  4. 「管理ホスト › エージェントパック」から Windows / Linux 用のパックを DL して、端末で実行する"
  fi
  say ""
  say "  Wazuh ダッシュボード: MamorAI にログインして、左下の「Wazuh ダッシュボード」から開く（直接のアクセスは閉じています）"
  say "    非常時に元のログイン画面へ戻す: ${CB}sudo $DEST/installer/modules/30-wazuh-dashboard-frontdoor.sh revert${C0}"
  [[ "${CFG[WINDOWS_ADDON]:-no}" == yes ]] && say "  署名鍵のバックアップ: /root/mamorai-signing/（サーバーの外へ）"
  say "  ログ: $LOG"
}

# ---------------------------------------------------------------- main --------------------------------------------
STEPS=(preflight wazuh ro_users docker mamorai modules dashboard addon connect firewall)
TITLES=("事前チェック" "Wazuh（all-in-one）" "MamorAI 用の読み取り専用ユーザー" "Docker" "MamorAI" "Wazuh 側の仕上げ（indexer の調整・監査ログ・改ざん監視・遮断用ユーザー・登録パスワード）" "Wazuh ダッシュボードを MamorAI のログインの後ろへ" "Windows 用アドオン" "つなぎ方（エージェントパック / Tailscale）" "ファイアウォール")
TOTAL=${#STEPS[@]}

# permissions the container (non-root user) needs; cheap and idempotent, so done on every run
[[ -d "$DEST/secrets" ]] && chmod 755 "$DEST/secrets"
[[ -d "$DEST/addon" ]] && chmod -R a+rX "$DEST/addon"
if [[ $CHECK_ONLY -eq 1 ]]; then CUR_STEP=""; s_check && exit 0 || exit 1; fi
if [[ $RESUME -eq 0 && -s "$STATE" ]]; then
  if [[ $INTERACTIVE -eq 1 ]]; then read -r -p "  前回のインストールの記録があります。続きから実行しますか？ (y=続きから / n=最初から) [y]: " a; [[ "${a:-y}" =~ ^[yY] ]] && { RESUME=1; load_kv "$ANS"; } || : >"$STATE"
  else RESUME=1; load_kv "$ANS"; fi
fi
if [[ $REINSTALL_APP -eq 1 ]]; then
  load_kv "$ANS"
  say "${CY}MamorAI だけを入れ直します。MamorAI のデータ（ユーザー・設定・相談の履歴）と .env は消えます。Wazuh はそのままです。${C0}"
  if [[ $INTERACTIVE -eq 1 ]]; then read -r -p "  続けますか？ (yes と入力) : " a; [[ "$a" == yes ]] || { say "中止しました"; exit 2; }; fi
  [[ -f "$DEST/docker-compose.yml" ]] && (cd "$DEST" && docker compose down -v >/dev/null 2>&1 || true)
  rm -f "$DEST/.env"
  [[ -f "$SECRETS" ]] && sed -i '/^APP_ADMIN_PASSWORD=/d; /^APP_ADMIN_MUST_CHANGE=/d' "$SECRETS"
  [[ -f "$STATE" ]] && sed -i '/^ro_users$/d; /^mamorai$/d; /^modules$/d; /^connect$/d' "$STATE"
  log "reinstall-mamorai: MamorAI data, .env and admin password removed"
fi
gather
summary_of_answers
# a newer package on a server where MamorAI is already installed: update /opt/edr-console and rebuild first
done_step mamorai && sync_app
for i in "${!STEPS[@]}"; do
  st="${STEPS[$i]}"
  if done_step "$st" && [[ "$st" != preflight ]]; then printf '\n%s==> [%s/%s] %s%s ... 済み（スキップ）\n' "$CC" "$((i+1))" "$TOTAL" "${TITLES[$i]}" "$C0"; continue; fi
  step "$st" "$((i+1))" "${TITLES[$i]}"
  "s_$st"
  mark_done "$st"
done
CUR_STEP="check"
if s_check; then CUR_STEP=""; finish_message; log "----- finished OK -----"
else CUR_STEP=""; say ""; warn "一部の確認が NG です。上の表示とログ（$LOG）を確認してください。直したら sudo ./install.sh --check"; finish_message; exit 1; fi
