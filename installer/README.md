# MamorAI installer modules

Every protection that MamorAI adds to a server is written as a module here and applied by `install.sh`. Each module is idempotent and has `apply` / `verify` (and `revert` where a
break-glass is needed). Run them as root on the Wazuh manager host.

| module | what it does | break-glass |
|---|---|---|
| `20-mamorai-wazuh-ingest.sh` | Wazuh reads MamorAI's audit log (journald `mamorai`), decoder + rules 1007xx | – |
| `30-wazuh-dashboard-frontdoor.sh` | Wazuh dashboard on loopback under `/wazuh`, proxy auth; only reachable through MamorAI (password + TOTP) | `revert` restores the dashboard's own login |
| `40-self-monitoring.sh` | syscheck on Wazuh rules/config, dashboard/indexer security config and the MamorAI files; rules 10073x | `revert` |
| `50-wazuh-ar-user.sh` | Wazuh API user `mamorai-ar` that may only run active responses (Windows host actions, EDR-121) | `revert` |
| `55-wazuh-enrollment-password.sh` | agent enrollment password (existing or new) → handed to MamorAI, put into every agent pack (EDR-137) | – |
| `60-tailscale.sh` | optional: manager joins the tailnet with the user's auth key, tailscale0 firewall rules, key + address handed to MamorAI (EDR-139) | `revert` |

MamorAI itself (TOTP MFA, sign-in throttling, step-up approvals, API token limits, kill switch) is configured by
environment variables with secure defaults — see `.env.example` (`MFA_REQUIRED`, `LOGIN_*`, `STEP_UP_APPROVALS`,
`API_TOKEN_*`, `AUTO_HOLD_MAX_CHANGES_10MIN`, `WAZUH_DASHBOARD_*`).

Lost authenticator: `docker exec edr-console node server/dist/cli.js user mfa-reset <email>`.

User-facing setup (to be read by the user's AI assistant): `docs/setup/`.
