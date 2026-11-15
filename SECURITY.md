# Security / セキュリティ

## 連絡方法

セキュリティ上の問題を見つけた場合は、**公開の Issue には書かず**、GitHub の「Security」タブにある **Report a vulnerability**（非公開の報告）から連絡してください。

## 凍結版についての注意

このリポジトリは凍結版です。報告は読みますが、**修正版を出すことは約束できません**。
影響が大きいものは、README の「既知の制限・問題」に追記して、利用者が判断できるようにします。

## 利用者の方へ

- 管理画面（:8444）をインターネットに直接公開しないでください。LAN か VPN（Tailscale など）の内側で使ってください
- 管理者のパスワードと TOTP、`/root/mamorai-signing/` のコード署名鍵、`.env`（`APP_SECRET` など）は、サーバーの外に漏らさないでください。`APP_SECRET` と MamorAI の DB が両方漏れると、保存した SSH 鍵などを復号されるおそれがあります
- 依存パッケージの既知の問題は README の「既知の制限・問題」を参照してください

---

## Reporting

Please **do not open a public issue**. Use **Report a vulnerability** on the repository's **Security** tab (private report).

## Frozen edition

This repository is frozen. Reports will be read, but **fixes are not guaranteed**. Significant issues will be documented in the README's known limitations so users can decide.

## For users

- Do not expose the console (:8444) directly to the internet; use it on your LAN or over a VPN (e.g. Tailscale).
- Keep the admin password and TOTP, the code-signing key in `/root/mamorai-signing/` and `.env` (`APP_SECRET` etc.) private. If both `APP_SECRET` and the MamorAI database leak, the stored SSH keys can be decrypted.
