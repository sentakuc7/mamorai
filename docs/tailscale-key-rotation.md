# Tailscale の認証キーを入れ替える（90 日ごと）

MamorAI の画面では、ⓘ マーク →「入れ替えの手順を見る」から、同じ内容のページ（`/help/tailscale-key`）を開けます。

## 要点

- Tailscale の認証キーは最長 90 日で期限が切れます（Tailscale の仕様で、無期限にはできません）。
- 期限が切れても、**すでに tailnet に入っている端末やサーバーはつながったまま**です。キーを使うのは、エージェントパックで**新しく**端末を入れるときだけです。
- MamorAI は期限の 14・7・3・1・0 日前に知らせます。期限が切れたあとは、毎日 1 回知らせます。
  - エージェントパックの画面: 注意書きと「キー残り N 日」の表示
  - Wazuh のアラート: 100764（L8）。期限切れは 100765（L10）
  - Discord（設定してある場合）

## 手順（5 分ほど）

1. Tailscale の管理画面で **Settings › Keys** を開き、**Generate auth key…** を押す。
2. 次のとおりに設定して **Generate key** を押す。

| 項目 | 設定 | 理由 |
|---|---|---|
| Description | `mamorai agent pack` | あとで見分けるため |
| Reusable | オン | 多くの端末で同じキーを使うため |
| Expiration | 90 days | 選べる最長の期間 |
| Ephemeral | オフ | オンだと、オフラインになった端末が消えてしまう |
| Tags | オン → `tag:mamorai` | タグ付きの端末は、端末の鍵に期限がなくなる（180 日で外れない） |
| Pre-approved | 表示されていればオン | 端末ごとの承認を省くため（端末の承認を有効にしている tailnet だけに出る項目） |

3. 表示された `tskey-auth-…` をコピーする。この画面を閉じると、二度と表示されない。チャットやメールには貼らない。
4. MamorAI の **設定 › エージェントパック › 秘密情報** で、キーを貼り付けて有効期限（90 日後の日付）を入れ、「保存」を押す。
   コマンドで入れる場合は、次のように実行する（キーはコマンド引数ではなく stdin から渡す）。
   ```bash
   read -rs K && printf '%s' "$K" | docker compose exec -T edr-console node server/dist/cli.js agent-pack secret tailscale-key 2027-01-23; unset K
   ```
5. エージェントパックが新しい版（rN）になり、変更点に「Tailscale の認証キーを更新」と出ることを確認する。
6. Tailscale の Keys の一覧で、古いキーを **Revoke** する。すでにつながっている端末には影響しない。

## 最初に 1 回だけやっておくこと

- `tag:mamorai` を作る。場所は Access controls › Definitions › Tags › Create tag で、Tag owner は `autogroup:admin`。
- Wazuh の manager（MamorAI のサーバー）は、Machines で端末の「…」から **Disable key expiry** にする。
  - タグ付きのキーで参加した端末は、最初から期限がない。
  - 人の名前で参加した端末は、既定で 180 日経つと外れる。
