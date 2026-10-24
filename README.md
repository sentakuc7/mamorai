<h1 align="center">MamorAI（マモライ）</h1>

<p align="center">
  <b>AI ops console for Wazuh — see the attack, let AI investigate, auto-patch and auto-block when you say so.</b><br>
  <b>Wazuh 用 AI 運用コンソール — 攻撃を見て、AI に調べさせて、任せると決めたら自動でパッチと遮断まで。</b>
</p>

<p align="center">
  <a href="#english">English</a> · <a href="#日本語">日本語</a> · <a href="#roadmap--ロードマップ">Roadmap</a> · <a href="#faq">FAQ</a>
</p>

<p align="center">
  <img alt="Status" src="https://img.shields.io/badge/status-pre--release-orange">
  <img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0-blue">
  <img alt="Wazuh" src="https://img.shields.io/badge/Wazuh-4.x-3b82f6">
  <img alt="Docker" src="https://img.shields.io/badge/docker-compose-2496ED">
</p>

> **⭐ Star / 👁 Watch this repo to get notified when v0.1 ships (target: late November 2026).**
> **⭐ Star / 👁 Watch しておくと v0.1 公開（2026 年 11 月下旬予定）時に通知が届きます。**

---

<p align="center">
  <img src="docs/images/overview.png" alt="Attack visualization overview" width="900">
</p>

---

## English

### What is MamorAI?

MamorAI is a self-hosted web console that sits on top of your existing **[Wazuh](https://wazuh.com/)** deployment and adds three things:

| | Feature | Status |
|---|---|---|
| 🌐 | **Attack Visualization** — 3D world map of inbound attacks, per-country / per-rule breakdown, hourly timeline, live updates. The thing that went viral. | v0.1 |
| 🔍 | **AI Sidekick** — ask "what is this alert?" and get an investigation with evidence pulled from the Wazuh indexer, vulnerability data and the process tree. | v0.2 |
| ✅ | **Approval Queue** — the AI can *propose* actions (block IP, restart service, patch), but nothing changes state until a human approves it. Every command, diff and rollback is shown before you click. | v0.3 |
| ⚡ | **Autonomous Response (coming soon)** — turn the dial up and MamorAI acts on its own: **auto-patch** hosts when a critical CVE lands, **auto-block** the source the moment Wazuh detects an intrusion, auto-rollback if a fix breaks something. Opt-in per host, with a kill switch. | v0.4 |

It reads the Wazuh indexer directly, so there is nothing to install on your agents.

### ⚡ Autonomous Response — coming soon

Investigation is only half the job. MamorAI is built to **close the loop**:

| Trigger (from Wazuh) | What MamorAI does on its own |
|---|---|
| Critical CVE reported on a managed host (e.g. the PHP2Shell wave) | Checks exposure, stages the patch, **applies it and verifies** the service — within minutes, not days |
| Brute-force / web-shell / lateral-movement detection | **Blocks the source** at the firewall or fail2ban, isolates the host if needed, notifies you |
| A fix fails or a service does not come back | **Rolls back** to the pre-change snapshot and retries within the approved scope |

You decide how far it goes with **autonomy levels**:

| Level | Behaviour |
|---|---|
| L0 | Propose only |
| L1 | Propose → human approves → execute *(default)* |
| L2 | Read-only investigation runs automatically; changes still need approval |
| L3 | **Low-risk changes (patch, block, restart) execute automatically** — with pre-change snapshot, auto-rollback, a kill switch, and a full audit trail |

Every autonomous action is logged, reversible, and visible in the approval queue after the fact. The core design (EDR-68 autonomy levels, EDR-87/88 self-healing retries, EDR-90 self-defence) is already running in the lab; it ships after v0.3.

### Design principles

1. **Human-in-the-loop by default, autonomous by choice.** Read-only investigation runs freely; anything that writes goes through the approval queue. Autonomous response (L3) is opt-in per host, snapshot-backed and reversible.
2. **Runs where your data is.** Docker Compose on your own box. Works with local LLMs (Ollama) as well as hosted APIs.
3. **Wazuh stays the source of truth.** MamorAI never replaces the Wazuh manager or dashboard — it adds a layer on top.
4. **Everything is auditable.** Every AI proposal, approval and execution is logged — and can be fed back into Wazuh.

### Quick start (v0.1 — not yet released)

```bash
git clone https://github.com/sentakuc7/mamorai.git
cd mamorai
cp .env.example .env     # set WAZUH_INDEXER_URL / USER / PASSWORD
docker compose up -d
# open http://localhost:3000
```

### Screenshots

| Alerts (AI-explained, triaged) | Process tree |
|---|---|
| ![](docs/images/ss-alerts.png) | ![](docs/images/ss-process-tree.png) |

*Screenshots are from the pre-rename lab build ("EDR Console"); hostnames and IPs are masked.*

---

## 日本語

### MamorAI とは

既存の **[Wazuh](https://wazuh.com/)** 環境の上に載せるセルフホスト型の Web コンソールです。追加するのは次の 3 つ。

| | 機能 | 状態 |
|---|---|---|
| 🌐 | **攻撃可視化** — 世界地図 3D に着弾する攻撃、国別・ルール別の内訳、1 時間単位の時系列、ライブ更新。X でバズった画面です。 | v0.1 |
| 🔍 | **AI Sidekick** — 「このアラート何？」と聞くと、Wazuh indexer・脆弱性情報・プロセスツリーから根拠を集めて調査結果を返します。 | v0.2 |
| ✅ | **承認キュー** — AI は Action（IP 遮断・サービス再起動・パッチ適用）を *提案* するだけ。人が承認するまで何も変わりません。コマンド全文・差分・ロールバック手順を見てからクリックできます。 | v0.3 |
| ⚡ | **自律対処（カミングスーン）** — 自律度を上げると MamorAI が自分で動きます。**緊急性の高い脆弱性が出たら AI がホストにパッチを当て**、**Wazuh が侵入を検知したら送信元を自動遮断**、修正が失敗したら自動ロールバック。ホスト単位の opt-in、キルスイッチ付き。 | v0.4 |

Wazuh indexer を直接読むので、エージェント側に入れるものはありません。

### ⚡ 自律対処 — カミングスーン

調べて終わりではなく、**対処まで閉じる**ために作っています。

| きっかけ（Wazuh の検知） | MamorAI が自動でやること |
|---|---|
| 管理ホストに Critical な CVE（例: PHP2Shell の波） | 影響有無を確認 → パッチを準備 → **適用してサービスを検証**。数日ではなく数分で |
| 総当たり / Web シェル / 横展開の検知 | **送信元をファイアウォール・fail2ban で遮断**、必要ならホストを隔離して通知 |
| 修正が失敗した / サービスが戻らない | 変更前スナップショットへ**自動ロールバック**し、承認済みの範囲内で再試行 |

どこまで任せるかは **自律度レベル** で決めます。

| レベル | 動作 |
|---|---|
| L0 | 提案のみ |
| L1 | 提案 → 人が承認 → 実行（*既定*） |
| L2 | 読み取り専用の調査は自動、変更は承認必須 |
| L3 | **低リスクの変更（パッチ・遮断・再起動）は自動実行** — 変更前スナップショット・自動ロールバック・キルスイッチ・監査ログ付き |

自動で行った操作もすべて記録され、取り消せて、承認キューに事後表示されます。基盤となる設計（EDR-68 自律度、EDR-87/88 自己修復リトライ、EDR-90 自己防御）はラボで稼働済みで、v0.3 の次に出します。

### 設計方針

1. **既定は人が承認、任せるかは選べる。** 読み取り専用の調査は自由に走り、書き込みは承認キューを通ります。自律対処（L3）はホスト単位の opt-in で、スナップショット付き・取り消し可能です。
2. **データのある場所で動く。** 自分のマシンで docker compose。ローカル LLM（Ollama）でも、各社 API でも動きます。
3. **Wazuh が正。** Wazuh manager / dashboard を置き換えるものではなく、その上に 1 層足すものです。
4. **全部ログに残る。** AI の提案・承認・実行はすべて記録され、Wazuh 側に戻して監視することもできます。

### クイックスタート（v0.1 — 未公開）

```bash
git clone https://github.com/sentakuc7/mamorai.git
cd mamorai
cp .env.example .env     # WAZUH_INDEXER_URL / USER / PASSWORD を設定
docker compose up -d
# http://localhost:3000 を開く
```

---

## Roadmap / ロードマップ

| Version | Target | Scope |
|---|---|---|
| **v0.1** | 2026-11 下旬 | Attack visualization overview, alert list (read-only), local auth, `docker compose up` |
| v0.2 | 2026-12 | AI Sidekick (investigation only), process tree, vulnerability context |
| v0.3 | 2027-Q1 | Approval queue, Action execution with rollback, audit log |
| **v0.4** | 2027-Q1 | **⚡ Autonomous Response**: auto-patch on critical CVE, auto-block on intrusion, autonomy levels L0–L3, kill switch, Sentinel (auto-triggered investigation) |
| later | — | Cloud providers (Lightsail / EC2 / GCE / Hyper-V), installer & agent-rollout wizard |

Progress is tracked publicly in this repo's Issues once v0.1 lands.

## FAQ

**Is it open source?**
The core (visualization, Wazuh connector, console UI) will be released under **AGPL-3.0**. Some advanced automation features may ship separately later. The core will always be enough to run the attack map on your own data.

**Does the AI block attackers / patch hosts automatically?**
Only if you tell it to. Out of the box MamorAI proposes and a human approves (L1). Raise a host to L3 and it will auto-patch critical CVEs and auto-block detected intruders — with a pre-change snapshot, automatic rollback and a kill switch. Coming in v0.4.

**Which LLMs?**
Anything with an OpenAI-compatible or Anthropic API, plus Ollama for fully local operation. Model choice is a config value.

**Does it send my logs anywhere?**
Only to the LLM endpoint you configure. With Ollama, nothing leaves your network.

**Wazuh version?**
Developed against Wazuh 4.x (indexer = OpenSearch).

## Contact

- X: [@hjkworld_ai](https://x.com/hjkworld_ai)
- note (JP): [AI職人になろうと思うHjK](https://note.com/hjkworld)

## License

Core: AGPL-3.0 (to be published with v0.1). Screenshots and videos in this README: CC BY 4.0.
