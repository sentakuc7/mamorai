# ホストの AI スキャンと遮断操作（EDR-121）

MamorAI の「管理ホスト」画面で、サーバーにもクライアント PC にも同じ操作ができます。

| 機能 | 何をするか | 承認 |
|---|---|---|
| **ホストを AI でスキャン** | 提供しているサービス（待ち受けポート → プロセス → サービス、外からどこまで届くか）、入っているソフト、ログインしているユーザー、使われ方（時間帯・プロセス・通信相手）、リスクを「ホストカルテ」に並べる | 不要（読み取りだけ） |
| **遮断操作** | サービスを止める／ポートを遮断／相手 IP を遮断／端末を隔離（とその解除） | **毎回必要**（自動承認・自動再実行の対象外） |

## 1. 何もしなくても使えるもの

- **エージェントの取り込み**: Wazuh に登録されているエージェントは、10 分ごとに「エージェントだけ」のホストとして自動で取り込まれます（`HOST_AGENT_SYNC_MIN`）。すぐ取り込みたいときは「Wazuh から取り込む」を押します。取り込んだホストを削除すると、次回以降は取り込みません。
- **スキャン**: Wazuh 4.8 以降のインベントリ（`wazuh-states-inventory-*`）、脆弱性、設定監査、アラートの集計を使います。SSH を登録したサーバーでは、固定の読み取り専用コマンド（`ss`、`systemctl`、`who`／`last`、cron、docker、Web サーバーの設定）も使います。このコマンドを AI が作ることはありません。
- **AI について**:
  - AI に渡すのは集計した事実だけで、生のログは渡しません。
  - ユーザー名は仮名（U01 …）に置き換えて送ります。この設定は「設定 › ホストスキャン」で変えられます。
  - AI の記述には根拠の ID（`port:tcp/445` など）が必須で、根拠が実在しない項目は捨てます。
  - LLM を設定していない場合や `HOST_SCAN_AI=false` の場合は、集めた事実だけを表示します。
- **定期スキャン**:
  - 既定は本番が毎日、ステージングが毎日、検証が週 1 です。
  - 全体の頻度は「設定 › ホストスキャン」で、ホストごとの上書きは「編集」で変えられます。
  - 前回のスキャンから新しく増えた「外から届くポート」「管理者アカウント」「リモート操作ソフト」は、Wazuh のルール 100745（level 10）でアラートになります。
- **Linux（SSH あり）の遮断**:
  - SSH の鍵と sudo（NOPASSWD）があればそのまま使えます。
  - nftables を使い、無ければ iptables を使います。
  - 通信を変える操作では、先に「一定時間後に自動で元に戻す」予約をホスト側に入れます（`HOST_ACTION_LINUX_AUTOREVERT_SEC`、既定 180 秒）。MamorAI が SSH で入り直せたときだけ予約を取り消すので、締め出されることはありません。

## 2. Windows の遮断を使うための準備（3 段階）

Windows の端末には SSH で入りません。Wazuh の自動対処（active response）で、端末に置いた**署名つきアドオン**を動かします。

### 2.1 Wazuh 側: ルールと API ユーザー（Wazuh manager のサーバーで実行）

```bash
cd /opt/edr-console/installer/modules        # MamorAI を置いた場所
sudo ./20-mamorai-wazuh-ingest.sh apply      # アドオンの結果を読むデコーダーとルール（mamorai_ar_rules.xml）を入れる
sudo MAMORAI_ENV=/opt/edr-console/.env ./50-wazuh-ar-user.sh apply
cd /opt/edr-console && docker compose up -d  # 新しい資格情報を読み込む
```

`50-wazuh-ar-user.sh` は、自動対処の実行（`active-response:command`）**だけ**ができる Wazuh API ユーザー `mamorai-ar` を作り、`WAZUH_AR_USER` / `WAZUH_AR_PASSWORD` を `.env` に書きます。パスワードは画面に出しません。MamorAI が普段使う API ユーザーは読み取り専用のままです。元に戻すときは `./50-wazuh-ar-user.sh revert` を実行します。

### 2.2 アドオンを作る（Linux で 1 回）

```bash
sudo apt install osslsigncode
cd /opt/edr-console                                   # MamorAI を置いた場所
sudo installer/windows/build-addon.sh --keys /root/mamorai-signing --out ./addon
```

`./addon` は MamorAI のコンテナに読み取り専用でつながっていて（docker-compose.yml の `./addon:/app/addon:ro`）、**Windows 用のエージェントパックに自動で入ります**。作り直すと 10 分以内にパックが新しい版になります（[agent-pack.md](agent-pack.md)）。

- 初回は、**あなたの環境専用のコード署名証明書**を `--keys` のフォルダに作ります。
  - `signing.key` は秘密鍵です。リポジトリやチャットに置かず、バックアップしてください。
  - 2 回目以降も同じ鍵で署名します。鍵を変えると、端末側で信頼し直す必要があります。
- 出力フォルダ（`addon/`）の中身:
  - `mamorai-ar.cmd`: 入口
  - `mamorai-ar.ps1`: 署名済みの本体
  - `mamorai-addon-signing.cer`: 証明書。公開してかまいません
  - `manifest.json`: 版、各ファイルの SHA-256、署名者
  - `Install-MamoraiAddon.ps1`: 端末用のインストーラー

### 2.3 端末に入れる

**おすすめ**: ホスト管理画面の「エージェントパック」から Windows 用パックを DL し、端末で `Install-EdrAgent.bat` を実行して「更新」（またはアドオンだけ）を選びます。共有フォルダからの無人配布もできます（[agent-pack.md](agent-pack.md)）。

アドオンだけを手で入れる場合は、出力フォルダを端末にコピーし、管理者として次を実行します。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-MamoraiAddon.ps1
```

インストーラーは次の順で進めます。

1. 各ファイルの SHA-256 を `manifest.json` と照合する
2. 署名者を照合する
3. Authenticode 署名を確認する
4. 証明書を「信頼されたルート」と「信頼された発行元」に入れる
5. `ossec-agent\active-response\bin` にファイルを置く
6. `active-responses.log` が Wazuh に転送されるようにする
7. その場で自己テストを行う（終了コード 0 なら成功）

**台数が多い場合**は、同じフォルダを読み取り専用の共有に置き、GPO のスタートアップスクリプト・Intune・PDQ などからこのインストーラーを呼びます。何度実行しても結果は同じです。

入れたら、MamorAI のホスト画面で「アドオンの版を確認」を押します。版が表示されれば遮断ボタンが使えるようになります。未導入の端末や版が古い端末では、遮断ボタンを押せません。

**更新**: `mamorai-ar.ps1` の `$AddonVersion` を上げて 2.2 をやり直すと、エージェントパックが自動で新しい版になります。それを配り直します。必要な最低限の版は `AR_ADDON_MIN_VERSION` で指定します。

#### 採用しなかった配り方

| 方法 | 理由 |
|---|---|
| Wazuh のグループ共有ファイルで配り、端末側で実行フォルダにコピーする | manager を乗っ取られると、全端末に任意のコードを配れてしまう。Wazuh が共有設定からのコマンド実行を既定で無効にしているのと同じ理由 |
| MamorAI から WinRM / SMB で押し込む | 端末の管理者資格情報を MamorAI に持たせることになる |
| WPK（独自署名のアップグレードパッケージ） | 独自 CA の信頼設定を全台に入れる必要があり、エージェント本体の更新扱い（再起動あり）になる。台数が多い環境では今後検討する |

## 3. 安全の仕組み

| 層 | 仕組み |
|---|---|
| 承認 | すべての遮断と解除が承認キューを通る。AI（Sidekick の `host_action`）は依頼できるが、実行は人の承認後だけ |
| 対象外 | 「遮断の対象外」に設定したホストは操作できない。Wazuh manager のエージェント（000）は常に対象外 |
| 守るアドレス | 保護アドレス（設定 › 保護アドレス）、Wazuh・MamorAI 自身、ループバックへの IP 遮断は拒否する。Windows アドオンも端末側で manager・ドメインコントローラーの遮断を拒否する |
| 止めないサービス | sshd、wazuh-agent、tailscaled、WazuhSvc、Tailscale、RPC、イベントログ、ファイアウォールなど、管理や監視に必要なものは止めない |
| 締め出し防止 | Linux は自動で元に戻す予約を入れてから適用する。Windows の隔離は、適用後 60 秒以内に manager とつながらなければその場で元に戻す |
| 隔離の中身 | Wazuh manager への 1514・1515 だけを残す。Linux は MamorAI からの SSH も、ノート PC は Tailscale も残す（遠隔で解除できるように）。DNS・AD は選べる |
| アドオン | 受け付ける操作は 9 種類だけで、任意のコマンドは実行しない。引数は端末側でも検査する。署名が無い・壊れている場合は実行されない（AllSigned） |
| 記録 | 依頼・実行・失敗・解除はすべて監査ログに残し、Wazuh に送る（ルール 100740〜100748、端末の結果は 100750〜100753） |
| 隔離の解除 | 自動では解除しない。`HOST_ACTION_ISOLATION_REMIND_HOURS` ごとに「まだ隔離中」と通知する |

**現地での戻し方**（manager とつながらなくなった Windows 端末）: 管理者として、`ossec-agent\active-response\bin` で次を実行します。

```powershell
'{"command":"add","parameters":{"extra_args":["unisolate","--id","mlocal"]}}' | .\mamorai-ar.cmd
```

## 4. 制限（v1.0）

- Linux の遮断ルールは再起動すると消えます（nftables / iptables の一時的なルール）。
- Windows の隔離は、ローカルのファイアウォール規則を一時的に無効にして実現しています。GPO で配られた規則は無効にできないため、GPO で通信を許可している場合はその分が残ります。
- SSH の無い Linux（エージェントだけ）は遮断できません。SSH を登録してください。
- macOS は対象外です。

## 5. Windows の更新（Windows Update・winget・再起動）— EDR-168 / アドオン v1.2.1・v1.3.0

Linux は Sidekick が `apply_change`（SSH）でパッケージを更新します。Windows（エージェントだけの端末）は、同じ自動対処アドオンを使って更新します。

| 操作 | 承認 | 中身 |
|---|---|---|
| 更新を確認（`win_updates` / ホスト画面「更新を確認」） | 不要（読み取りだけ） | Windows Update の未適用分（KB・MSRC の重要度・CVE 数・サイズ）、winget で更新できるアプリ、再起動待ちの有無、WSUS の有無、最終起動時刻 |
| 更新をインストール（`host_action op=update_install`） | 必要 | `wu`: security（既定）/ all / kb（`kbs` で KB 指定）/ none、`apps`: "all" または winget の ID の配列。端末の SYSTEM のタスク（`MamorAI-update-<id>`）がバックグラウンドで実行し、進み具合と結果を返す（最大 `WIN_UPDATE_WAIT_MIN` 分、既定 180）。**再起動はしない** |
| 再起動を予約（`host_action op=reboot`） | 必要（インストールとは別） | `minutes` 分後に再起動。サインイン中の人に予告が出る。起動時刻が変わったことを確認して完了。再起動の前なら「予約を取り消す」で止められる |

- 機能アップグレード（OS の版上げ）とドライバーは入れません。プレビュー版の更新は security では選びません。
- 「遮断の対象外」にしたホスト（AD・業務サーバーなど）でも、更新と再起動はできます（承認は必要）。
- ノート PC がバッテリー 30% 未満で放電中のときは、端末が開始を断ります。
- WSUS を使っている端末は WSUS で承認された更新だけが対象になります（確認結果に WSUS のアドレスが出ます）。
- winget は Windows 10 1809 以降 / Windows 11 / Windows Server 2025 の App Installer が必要です。Windows Server 2016 / 2019 ではアプリの確認は「使えません」と表示され、Windows Update だけ動きます。
- 取り消し: インストールした更新は自動では戻しません（設定 › Windows Update › 更新の履歴 › 更新プログラムをアンインストールする）。

アドオンを 1.2.1 以上にするには、manager で `installer/windows/build-addon.sh --keys <署名鍵のフォルダ> --out /opt/edr-console/addon` を実行し、エージェントパックを端末に入れ直します（パックの版が上がります）。

### 5.1 アドオン v1.3.0 で増えたこと

**ベンダー公式のアプリ更新（レシピ）**: winget はコンピューター全体に入れた Chrome などを更新できないことが多いため、次の 4 つはベンダーの公式 MSI で更新します。どれも「最新版をベンダーの API で調べる → MSI をダウンロード → Authenticode 署名が Valid かつ発行元が一致することを確認 → `msiexec /i /qn /norestart`」の順で、署名が合わなければ入れません。

| ID | 最新版の取得元 | 署名の発行元（O=） |
|---|---|---|
| Google.Chrome | versionhistory.googleapis.com | Google LLC |
| Microsoft.Edge | edgeupdates.microsoft.com | Microsoft Corporation |
| Mozilla.Firefox | product-details.mozilla.org | Mozilla Corporation |
| Zoom.Zoom | zoom.us/rest/download | Zoom Communications, Inc. |

それ以外のアプリは winget です（7-Zip は MSI に署名が無いため winget のみ）。確認結果のアプリ欄に「ベンダー公式」/「winget」が出ます。

**進み具合**: Windows Update は 1 件ずつダウンロードし、KB ごとに「待ち → ダウンロード中 → ダウンロード済み → インストール中 → 完了 / 失敗」を返します。インストール中は 5 分ごとに「インストール中（N 分）」を返すので、止まっているのか待っているのかが分かります。

**中止**: 実行中の更新は、ホスト画面の「中止」または Sidekick への「止めて」で止められます（承認が必要）。終わった KB はそのまま残り、残りはやりません。

**アドオンの自動更新（EDR-169）**: manager で `--publish-group windows` を付けて作ると、Wazuh の共有フォルダ（`/var/ossec/etc/shared/windows/mamorai-addon-*`）に置かれ、エージェントが数分で受け取ります。ホスト画面のアドオン欄に「v1.x.y に更新」が出るので、承認すると端末が

1. 共有フォルダのファイルのハッシュが manifest と一致するか
2. 新しいアドオンの署名が Valid で、**今入っているアドオンと同じ証明書**か
3. 版が今より新しいか

を確かめてから入れ替え、新しいアドオンで自己テスト（版の報告）をします。自己テストに失敗したら元のアドオンに戻します。署名鍵を変えたときと、1.3.0 より前のアドオンからは、エージェントパックの入れ直しが必要です。

```
sudo installer/windows/build-addon.sh --keys /root/mamorai-signing --out /opt/edr-console/addon --publish-group windows
```

### 5.2 再起動の案内と延期（アドオン v1.3.1）

サインイン中の人がいる端末で「再起動を予約」すると、その人の画面に日本語の案内（最前面・カウントダウン付き）が出ます。

| ボタン | 動き |
|---|---|
| 今すぐ再起動 | 1 分後に再起動（Windows の 1 分前予告が出ます） |
| 5分後 / 1時間後 / 4時間後 | その時刻まで延期。新しい時刻の 2 分前にもう一度案内を出します |
| 何も押さない | 承認した時間どおりに再起動 |

- 延期は何度でもできますが、**最初の案内から 4 時間より先**にはできません（超えるボタンは押せなくなります）。
- 延期されると承認カードに「サインイン中の人が 1 時間後に延期しました（14:05 に再起動）」と出て、MamorAI はその時刻まで待ってから起動を確認します。
- 誰もサインインしていない端末では案内は出さず、指定時間で再起動します（Windows 標準の予告文も日本語）。
- 取り消し: ホスト画面の「予約を取り消す」または Sidekick に「再起動をやめて」（`host_action op=reboot_cancel`、承認が必要）。
- 仕組み: SYSTEM のタスク `MamorAI-reboot-<id>` が時刻を管理し、案内はサインイン中の人の権限で動くタスク `MamorAI-rebootui-<id>` が出します（署名済みの複製 `C:\ProgramData\MamorAI\bin\mamorai-ar.ps1`、利用者は読み取りのみ）。答えは `C:\ProgramData\MamorAI\reboot\` に書かれ、SYSTEM 側は 0 / 5 / 60 / 240 以外と 4 時間を超える指定を受け付けません。
