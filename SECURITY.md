# Security / セキュリティ

## 連絡方法

セキュリティ上の問題を見つけた場合は、**公開の Issue には書かず**、GitHub の「Security」タブにある **Report a vulnerability**（非公開の報告）から連絡してください。

## 対応について

報告はすべて確認し、必要に応じて修正版を出します（時期は約束できません）。
すぐに直せないものは、README の「既知の制限・問題」に追記して、利用者が判断できるようにします。

## 利用者の方へ

- 管理画面（:8444）をインターネットに直接公開しないでください。LAN か VPN（Tailscale など）の内側で使ってください
- 管理者のパスワードと TOTP、`/root/mamorai-signing/` のコード署名鍵、`.env`（`APP_SECRET` など）は、サーバーの外に漏らさないでください。`APP_SECRET` と MamorAI の DB が両方漏れると、保存した SSH 鍵などを復号されるおそれがあります
- 依存パッケージの既知の問題は README の「既知の制限・問題」を参照してください

---

## Reporting

Please **do not open a public issue**. Use **Report a vulnerability** on the repository's **Security** tab (private report).

## Handling

Every report is reviewed and fixes are released as needed (no fixed timeline). Issues that cannot be fixed right away are documented in the README's known limitations so users can decide.

## For users

- Do not expose the console (:8444) directly to the internet; use it on your LAN or over a VPN (e.g. Tailscale).
- Keep the admin password and TOTP, the code-signing key in `/root/mamorai-signing/` and `.env` (`APP_SECRET` etc.) private. If both `APP_SECRET` and the MamorAI database leak, the stored SSH keys can be decrypted.
