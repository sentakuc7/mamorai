# エージェントパック（EDR-130）

端末に Wazuh エージェントを入れるための一式を、MamorAI のホスト管理画面から DL できます。Windows 用と Linux 用があります。

- **新しい端末にも、すでに入っている端末にも、同じパックを使えます**。インストーラーが「新規 / 更新 / アドオンだけ」を選びます。
- **版は自動で上がります**。MamorAI の設定、Windows 用アドオン、Wazuh の版、インストーラー本体のどれかが変わると、新しい版（rN）ができます。何が変わったかは画面に出ます。
- **GPO が無くても配れます**。共有フォルダに置いたパックを、各端末で `-Mode update -Unattended` で実行するだけです。
- **端末ごとに、入っているパックの版を表示します**。古い端末には「古い」と出ます。Windows はアドオンの版確認のとき、Linux は SSH スキャンのときに読み取ります。

## 1. はじめに設定する（管理者）

「設定 › エージェントパック」を開いて、次を設定します。

| 項目 | 内容 |
|---|---|
| Wazuh manager | エージェントの接続先。LAN・Tailscale・インターネット経由のうち、少なくとも 1 つを入れます |
| Wazuh エージェントの版 | `auto` にすると、manager と同じ版を Wazuh API から読みます |
| Windows | ノート PC 用とデスクトップ用のグループ、端末の種類（インストール時に聞く／どちらかに固定）、Sysmon とその設定ファイル |
| Linux | グループ、Tailscale、auditd、docker-listener、MamorAI 用 SSH（後述） |

グループは Wazuh 側に用意しておきます。存在しないグループを指定すると、エージェントの登録に失敗します。最初は `default` のままで構いません。

画面を使わずに設定するとき（コマンドで）:

```bash
docker compose exec edr-console node server/dist/cli.js agent-pack set '{"manager":{"lan":"10.20.30.10"}}'
docker compose exec edr-console node server/dist/cli.js agent-pack show
```

Windows 用アドオンは、`installer/windows/build-addon.sh --out ./addon` で作ると自動でパックに入ります（[host-actions.md](host-actions.md) 2.2）。アドオンが無くてもパックは作れますが、その場合は MamorAI からの遮断操作が使えません。

## 2. DL する

ホスト管理画面の右上にある「エージェントパック」を開きます。

- **Windows 用**:
  - 通常版は、Wazuh エージェントと Sysmon を端末がインターネットから取ってきます。
  - オフライン版は、それらを zip に同梱します（約 10 MB）。インターネットに出られない端末に使います。
- **Linux 用**: パッケージは端末が Wazuh の公式リポジトリから取ります。GPG で署名を確認します。
- **秘密情報は自動で入る**（EDR-137）:
  - 対象は Tailscale の認証キーと Wazuh の登録パスワード。一度登録すれば、すべてのパックに自動で入る。
  - 登録する方法は次の 3 つ。
    - セットアップのとき（`installer/modules/55-*`・`60-*`）
    - 画面の「設定 › エージェントパック › 秘密情報」
    - CLI: `echo "$KEY" | ... cli.js agent-pack secret tailscale-key [YYYY-MM-DD]`
  - MamorAI の中では暗号化して保存する。画面には表示しない。
  - キーを入れ替えると、パックは自動で新しい版になる。期限を登録しておくと、14 日前から知らせる。
- **暗号化 ZIP**（EDR-138）:
  - 秘密情報が入っているパックは、DL のたびに作るパスワードで暗号化する。ZipCrypto なので、Windows のエクスプローラーや unzip でそのまま開ける。
  - パスワードは DL 画面に表示する（コピー／テキストで保存）。MamorAI には残さない。
  - インストールが成功すると、展開したフォルダとその zip を自動で消す。残す場合は `-KeepFiles` / `--keep-files`。
  - 共有フォルダから実行した場合は消さない。
  - DL は監査ログに残り、Wazuh のルール 100761 になる。

DL できるのは、コンソールにログインした operator 以上です。API トークンでは DL できません。

## 3. 端末で実行する

| | Windows | Linux |
|---|---|---|
| 対話（1 台ずつ） | `Install-EdrAgent.bat` をダブルクリック | `sudo ./install-edr-agent-linux.sh` |
| 無人（更新） | `powershell -ExecutionPolicy Bypass -File \\srv\share\MamorAI-Agent-Windows-rN\Install-EdrAgent.ps1 -Mode update -Unattended` | `sudo ./install-edr-agent-linux.sh --mode update --yes` |
| 無人（新規） | `... -Mode install -DeviceType desktop -RegistrationPassword <pw> -Unattended` | `sudo ./install-edr-agent-linux.sh --mode install --password '<pw>' --yes` |
| アドオンだけ | `Install-AddonOnly.bat` / `-Mode addon` | （Linux にアドオンはありません） |
| 終了コード | 0 = 完了、1 = 失敗、2 = 中止 | 同じ |
| ログ | `C:\ProgramData\MamorAI\agent-install.log` | `/var/log/mamorai-agent-install.log` |

インストーラーは、実行のたびに次の安全確認をします。

- パックの全ファイルを `SHA256SUMS.txt` と照合する。MamorAI が作ったあとに変更されていれば止まる。
- Windows: Wazuh の MSI、Sysmon、Tailscale は、正しい発行元の Authenticode 署名があるものだけ実行する。アドオンは、自前の証明書の署名とマニフェストの両方を確認する。
- 更新では登録を消さない。エージェントは、パックより古いときだけ版を上げ、新しい版を下げることはしない。

## 4. Linux: MamorAI から操作できるようにする（選択式）

設定で「選べるようにする」をオンにしておくと、インストールの途中で「MamorAI からこのサーバーをスキャン・操作できるようにしますか？」と聞かれます。答えの既定は「いいえ」です。`--mamorai-ssh` を付けると、聞かれずに設定します。

「はい」にすると、次のように設定します。

- 専用のユーザー `mamorai` を作ります。パスワードでのログインはできません。
- `authorized_keys` に MamorAI の公開鍵を入れます。このとき次の制限を付けます。
  - `from=` で、接続元を MamorAI のアドレスだけにします（設定画面の「接続元アドレス」）。
  - ポート転送と agent 転送を禁止します。
- sudo の設定は次のどちらかです。
  - あり: スキャンと遮断操作ができます。MamorAI は `sudo -n bash -c` でコマンドを実行するため、sudo の範囲は ALL です。
  - なし: スキャンだけになります。一般ユーザーが読める範囲しか見られません。
- 最後に、サーバーの hostkey の指紋を表示します。

インストールが終わったら、MamorAI のホスト画面でそのサーバーを開き、「パックで準備した SSH を使う」を押します。最初に接続したときに hostkey を記憶するので、インストーラーが表示した指紋と同じか確認してください。

取り消すときは、サーバーで次を実行します。

```bash
userdel -r mamorai; rm -f /etc/sudoers.d/90-mamorai
```

## 5. 版が上がるタイミング

MamorAI は 10 分ごと（`AGENT_PACK_CHECK_MIN`）と起動時、それに設定を保存したときに、パックの中身のハッシュを計算し直します。値が変わっていれば新しい版を記録し、`agent_pack.updated` として監査ログと Wazuh に残します。秘密情報を入れたかどうかでは、版は変わりません。

| 変わったもの | 例 |
|---|---|
| 設定 | manager のアドレス、グループ、Sysmon、Linux の SSH |
| Windows 用アドオン | `build-addon.sh` で作り直した |
| Wazuh の版 | manager を更新した（`auto` のとき） |
| インストーラー本体 | MamorAI を新しい版に更新した |

版の番号 rN は、Windows と Linux で一続きです。たとえば Windows が r1 で、Linux が r2 になります。

## 6. 関連するルール

| ルール | level | 内容 |
|---|---|---|
| 100760 | 3 | パックの DL、新しい版ができた |
| 100761 | 5 | 秘密情報入りのパック（暗号化 ZIP）を DL した |
| 100763 | 8 | Tailscale のキー / 登録パスワードを登録・変更した |
| 100764 | 8 | Tailscale のキーの期限が近い（14・7・3・1・0 日前） |
| 100765 | 10 | Tailscale のキーの期限が切れた（毎日 1 回） |

90 日ごとのキーの入れ替え手順: [tailscale-key-rotation.md](tailscale-key-rotation.md)
| 100762 | 8 | パックの設定が変わった |
