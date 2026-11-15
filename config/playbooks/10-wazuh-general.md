# Wazuh general (builtin)

## Querying
- `wazuh-alerts-*` holds only events that matched a rule. `wazuh-archives-*` (if enabled) holds every event, including Sysmon telemetry that matched no rule — use it for process trees and "what happened around this time".
- Always filter by time (`range` on `timestamp`, e.g. `now-24h`) and by `agent.id` or `agent.name` when the question is about one host. Use `size: 0` + `aggs` (terms on `rule.id`, `agent.name`, `data.srcip`, `data.win.eventdata.image`) before pulling samples.
- Useful fields: `rule.id`, `rule.level`, `rule.description`, `rule.groups`, `rule.mitre.id`, `agent.id/name/ip`, `data.srcip`, `data.srcuser`, `data.win.system.eventID`, `data.win.eventdata.{image,commandLine,parentImage,parentCommandLine,user,processGuid,parentProcessGuid,targetFilename,destinationIp,destinationPort,queryName,targetObject,hashes}`, `full_log`.
- Level meaning: 0-6 low, 7-11 medium, 12-14 high, 15+ critical.

## Sysmon event IDs
1 process create · 3 network connect · 5 process end · 7 image load · 8 CreateRemoteThread · 10 process access · 11 file create · 12/13/14 registry · 15 ADS · 22 DNS query · 23 file delete.
To reconstruct a chain: EID1 of the suspicious process → its `parentProcessGuid` → parent's EID1 (repeat); children = EID1 where `parentProcessGuid` = this guid; activity = EID 3/11/13/22 with the same `processGuid`.

## Common benign patterns
- `backgroundTaskHost.exe`, `taskhostw.exe`, `smss.exe`, `svchost.exe` started by `services.exe` with standard paths and Microsoft signatures are normal Windows behaviour; a generic "Suspicious Process" rule on them is usually a false positive unless the path or parent is unusual.
- Installers and updaters dropping EXE/DLL in `%TEMP%` (rule 92213) are common noise: check the parent (msiexec, setup.exe, Edge/Chrome updater) and whether the file is signed before escalating.
- PowerShell `__PSScriptPolicyTest_*.ps1` in Temp is normal.

## Linux / public servers
- SSH brute force: `sshd` rules 5710/5716/5720; fail2ban bans appear as custom rules (1003xx) when fail2ban logs are ingested. Count unique `data.srcip` and /24 ranges; distributed attacks hide under per-IP thresholds.
- Web attacks: Apache access-log rules 311xx and custom 1004xx. 200 responses to probes matter more than 404s.
- Before proposing a ban: confirm the IP is not a known-good client, a tailnet/LAN range, or a Cloudflare edge; prefer TTL-limited blocks; write down the rollback.
