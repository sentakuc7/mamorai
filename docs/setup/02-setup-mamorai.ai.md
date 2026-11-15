# MamorAI セットアップ 02: Wazuh と MamorAI を 1 台のサーバーに構築する（AI への指示書）

> **この文書の読み手は AI アシスタントです**。MamorAI を使い始める人（以下「利用者」）の代わりに、またはその横で、サーバーの構築を進めてください。
> - コマンドを直接実行できる AI（Claude Code など）は、利用者の許可を取ってから実行する。
> - そうでない AI は、コマンドを 1 ブロックずつ示して、利用者に貼り付けてもらう。
>
> 前提: `01-prepare-tailscale.ai.md` が済んでいること（Tailscale を使う場合だけ）。
> 今後の予定: この手順は、1 本のセットアップスクリプトにまとめる（EDR-91）。それまでは、この文書の順番どおりに進める。

## あなた（AI）が守ること

1. **パスワード・キー・トークンを画面やチャットに出さない**。生成した値はファイル（root だけが読める 600）か、パイプで次のコマンドに渡す。`cat` で中身を表示しない。
2. **Tailscale のキーは、利用者がサーバーのターミナルに直接入力する**（`read -s` のプロンプト）。チャットで受け取らない。
3. 各手順の前に「これから何を変えるか」を 1 行で利用者に伝え、確認を取ってから実行する。
4. 失敗したら、エラーメッセージとログの末尾を利用者に見せ、推測で別の手順に進まない。
5. 社内の本番サーバーではなく、MamorAI 専用に用意したサーバーで行う。

## 02-0. 最初に確認すること

利用者に次を聞き、メモしておいてください。

| 質問 | 例 | 使う場所 |
|---|---|---|
| つなぎ方 | LAN だけ / **Tailscale** / 公開アドレス | 02-6・02-7 |
| サーバーの LAN アドレス | 10.20.30.10 | エージェントパック |
| サーバーの OS | Ubuntu 22.04 / 24.04、RHEL 9 系 | 全体 |
| 管理者のメールアドレス | admin@example.com | MamorAI の最初の管理者 |
| AI の API キー（任意） | OpenRouter / Anthropic / ローカルの Ollama | MamorAI の AI 機能 |

サーバーの目安は 4 vCPU・8 GB メモリ・ディスク 100 GB 以上です（Wazuh の all-in-one の要件）。台数が多いときは増やしてください。

## 02-1. Wazuh を入れる（all-in-one）

1. Wazuh の公式 Quickstart（https://documentation.wazuh.com/current/quickstart.html ）を開き、**最新のインストールコマンド**を確認する。版の番号を推測で書かない。
   - 例（4.14 系の場合）: `curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a`
2. 終わると `wazuh-install-files.tar` ができる。その中の `wazuh-passwords.txt` を root だけが読める場所に置く。
   ```bash
   sudo mkdir -p /root/wazuh && sudo tar -xf wazuh-install-files.tar -C /root/wazuh && sudo chmod -R go-rwx /root/wazuh
   ```
   中身は表示しない。ダッシュボードの admin パスワードは、利用者が自分で確認する（`sudo grep -A1 "'admin'" /root/wazuh/wazuh-install-files/wazuh-passwords.txt`）。
3. 確認: `sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard` がすべて `active`。

## 02-2. MamorAI 用の読み取り専用ユーザーを作る

MamorAI は、Wazuh を**読み取り専用**のユーザーで読みます。下のブロックを root で実行してください。パスワードは自動で生成され、`/root/mamorai/secrets.env` にだけ書かれます。

```bash
sudo bash -c '
set -euo pipefail
umask 077; mkdir -p /root/mamorai
PWF=/root/wazuh/wazuh-install-files/wazuh-passwords.txt
get() { awk -v u="$1" "\$0 ~ \"username: .?\"u\".?\$\" {getline; sub(/.*password: /,\"\"); gsub(/\x27/,\"\"); print; exit}" "$PWF"; }
ADMIN_PW=$(get admin); API_PW=$(get wazuh)
gen() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print(\"Ma\"+\"\".join(secrets.choice(a) for _ in range(26))+\"7_.x\")"; }
RO_IDX=$(gen); RO_API=$(gen)
# indexer: internal user edr-console-ro with the built-in read-all role
curl -sk -u "admin:$ADMIN_PW" -X PUT https://127.0.0.1:9200/_plugins/_security/api/internalusers/edr-console-ro \
  -H "Content-Type: application/json" -d "{\"password\":\"$RO_IDX\",\"backend_roles\":[\"readall\"]}" | grep -q "\"status\":\"\(CREATED\|OK\)\"" && echo "indexer user OK"
# Wazuh API: user edr-console-ro with the built-in readonly role
T=$(curl -sk -u "wazuh:$API_PW" -X POST "https://127.0.0.1:55000/security/user/authenticate?raw=true")
UID_=$(curl -sk -H "Authorization: Bearer $T" -H "Content-Type: application/json" -X POST https://127.0.0.1:55000/security/users -d "{\"username\":\"edr-console-ro\",\"password\":\"$RO_API\"}" | python3 -c "import json,sys; print(json.load(sys.stdin)[\"data\"][\"affected_items\"][0][\"id\"])")
RID=$(curl -sk -H "Authorization: Bearer $T" "https://127.0.0.1:55000/security/roles?search=readonly" | python3 -c "import json,sys; print(next(r[\"id\"] for r in json.load(sys.stdin)[\"data\"][\"affected_items\"] if r[\"name\"]==\"readonly\"))")
curl -sk -H "Authorization: Bearer $T" -X POST "https://127.0.0.1:55000/security/users/$UID_/roles?role_ids=$RID" >/dev/null && echo "API user OK"
printf "WAZUH_INDEXER_PASSWORD=%s\nWAZUH_API_PASSWORD=%s\nAPP_SECRET=%s\nAPP_ADMIN_PASSWORD=%s\n" "$RO_IDX" "$RO_API" "$(openssl rand -hex 32)" "$(gen)" > /root/mamorai/secrets.env
echo "written /root/mamorai/secrets.env (not shown)"
'
```

`indexer user OK` と `API user OK` の 2 行が出れば成功です。

## 02-3. MamorAI を入れる

```bash
sudo apt-get install -y docker.io docker-compose-v2 git || sudo dnf install -y docker docker-compose-plugin git
sudo systemctl enable --now docker
sudo git clone https://github.com/sentakuc7/mamorai.git /opt/edr-console
cd /opt/edr-console
sudo mkdir -p secrets addon && sudo cp /etc/wazuh-indexer/certs/root-ca.pem secrets/wazuh-root-ca.pem
sudo bash -c 'cp .env.example .env && chmod 600 .env
  while IFS="=" read -r k v; do sed -i "s|^$k=.*|$k=$v|" .env; done < /root/mamorai/secrets.env'
```

続けて `.env` の次の項目を、02-0 で聞いた値に書き換えます。`sed` を使い、値を表示しないこと。

- `APP_BASE_URL=https://<サーバーの LAN アドレス>:8444`
- `APP_ADMIN_EMAIL=<管理者のメールアドレス>`
- `WAZUH_NAME=<サーバー名>`
- AI を使う場合: `LLM_PROVIDER` とその API キー（`OPENROUTER_API_KEY` など）。キーは利用者にターミナルで入力してもらう。

```bash
cd /opt/edr-console && sudo docker compose up -d --build
sudo docker compose ps          # edr-console が Up になれば OK
```

## 02-4. Wazuh 側の仕上げ（モジュール）

どのモジュールも、何度実行しても同じ結果になります。`verify` で状態を確認できます。

```bash
cd /opt/edr-console/installer/modules
sudo ./20-mamorai-wazuh-ingest.sh apply        # MamorAI の監査ログを Wazuh で監視
sudo ./40-self-monitoring.sh apply             # Wazuh / MamorAI の設定ファイルの改ざん監視
sudo MAMORAI_ENV=/opt/edr-console/.env ./50-wazuh-ar-user.sh apply   # Windows の遮断操作用 API ユーザー
sudo ./55-wazuh-enrollment-password.sh apply   # エージェント登録パスワード → MamorAI に保存（パックに自動で入る）
cd /opt/edr-console && sudo docker compose up -d   # 50 の資格情報を読み込む
```

## 02-5. Windows 用アドオンを作る（Windows 端末を守る場合）

MamorAI のホスト画面から、Windows 端末のサービス停止やネットワーク遮断を行うための、署名つきスクリプトです。

```bash
sudo apt-get install -y osslsigncode || sudo dnf install -y osslsigncode
cd /opt/edr-console && sudo installer/windows/build-addon.sh --keys /root/mamorai-signing --out ./addon
```

`/root/mamorai-signing/signing.key` は署名用の秘密鍵です。サーバーの外の安全な場所へバックアップするよう、利用者に伝えてください。

## 02-6. つなぎ方の設定

**Tailscale の場合**（01 で用意したキーを使う）:

```bash
cd /opt/edr-console/installer/modules
sudo TS_EXPIRES=<キーの期限 YYYY-MM-DD> ./60-tailscale.sh apply
# → "Tailscale auth key (tskey-auth-...):" と聞かれるので、利用者に保存しておいたキーを貼り付けてもらう（画面には出ない）
```

manager を人の名前で参加させた場合は、Tailscale の管理画面の Machines で、manager の「…」から **Disable key expiry** にしてもらいます（180 日で外れないように）。`tag:mamorai` 付きのキーで参加した場合は不要です。

このモジュールは次をまとめて行います。

- manager を tailnet に参加させる。
- tailscale0 で 1514 / 1515 / 8444 / 22 を許可する。
- MamorAI に manager の tailnet アドレスを登録し、キーを暗号化して保存する。

**全員共通**（LAN のアドレスをエージェントパックに登録する）:

```bash
cd /opt/edr-console && sudo docker compose exec -T edr-console node server/dist/cli.js agent-pack set '{"manager":{"lan":"<サーバーの LAN アドレス>"}}'
```

**公開アドレスの場合**: `{"manager":{"public":"<DNS 名>"}}` も登録します。そのうえで、クラウドのファイアウォールで 1514 / 1515 を、接続してよい送信元だけに絞ってください。8444（MamorAI）と 9200 / 55000 は公開しないでください。

## 02-7. ファイアウォール（LAN）

ufw の例です（LAN が 10.20.30.0/24 の場合）。

```bash
sudo ufw allow from 10.20.30.0/24 to any port 1514,1515,8444,22 proto tcp
sudo ufw enable
```

Wazuh のダッシュボード（8443）は、MamorAI 経由でだけ見る構成にできます（`30-wazuh-dashboard-frontdoor.sh`）。その場合、8443 は開けません。

## 02-8. 最初のログイン

1. 利用者にブラウザで `https://<サーバーの LAN アドレス>:8444` を開いてもらう。自己署名証明書の警告が出るので、確認して進む。
2. 管理者のメールアドレスと、初回用のパスワードでログインする。初回用のパスワードは、利用者が自分で `sudo grep APP_ADMIN_PASSWORD /root/mamorai/secrets.env` で確認する。
3. パスワードを変え、認証アプリ（Google Authenticator など）で QR を読み取る。リカバリーコードは保存してもらう。

## 02-9. 完了の確認

| 確認 | 方法 |
|---|---|
| Wazuh が動いている | `sudo systemctl is-active wazuh-manager wazuh-indexer` |
| MamorAI に入れる | ブラウザでログインでき、TOTP を登録できた |
| 登録パスワードが MamorAI にある | `sudo ./55-wazuh-enrollment-password.sh verify` |
| （Tailscale）キーとアドレスが MamorAI にある | `sudo ./60-tailscale.sh verify` |
| エージェントパックを作れる | MamorAI の「管理ホスト › エージェントパック」で、Windows / Linux の版（rN）が表示され、エラーが無い |

ここまでできたら、利用者には次のように伝えてください。

- MamorAI の「管理ホスト › エージェントパック」から Windows 用 / Linux 用のパックを DL する。
- 端末で解凍して実行するだけで、Wazuh エージェントが入る。Tailscale のキーと登録パスワードは、パックに自動で入っている。
- 詳しくは `docs/agent-pack.md` を参照する。
