# MamorAI active-response add-on for Windows endpoints (EDR-121)
# Runs as SYSTEM, started by the Wazuh agent (wazuh-execd) when MamorAI sends "!mamorai-ar.cmd" after a human approved.
# It only does these operations and refuses anything else:
#   version | service-stop <name> | service-start <name> | block-port <tcp|udp> <port> | unblock-port <tcp|udp> <port>
#   block-ip <ip> | unblock-ip <ip> | isolate [allow-dns] [allow-ad] | unisolate
#   update-scan [--apps yes]                                  (read-only: Windows Update + winget upgrades)
#   update-install --wu security|all|none [--kb KB1,KB2] [--apps all|none|<id>,<id>]   (EDR-168, runs as a background task)
#   reboot --minutes <1-120> | reboot-cancel                 (1.3.1: a signed-in user gets a Japanese prompt and may
#                                                              postpone by 5 min / 1 h / 4 h, at most 4 h in total)
#   update-cancel                                             (1.3.0: stop the running update job)
#   pack-update <rev>                                         (1.3.3: run the agent pack published in the shared folder)
#   addon-update <x.y.z>                                      (1.3.0: replace this add-on with the signed copy that the
#                                                              manager published in the agent's shared folder)
#   common options: --id <run id> --ref <action id>
# update-install answers at once (phase=started) and hands the work to a one-shot SYSTEM scheduled task that runs this
# same signed file with -Job <file>; that task writes phase=progress lines and one phase=done line under the same id.
# Feature upgrades (category Upgrades) and drivers are never installed. Reboot is always a separate, approved operation.
# The result is written as one JSON line to active-response\active-responses.log, which the agent forwards to Wazuh
# (decoder "mamorai-ar", rules 100750-100753); MamorAI waits for that line.
# The file is Authenticode-signed; mamorai-ar.cmd runs it with -ExecutionPolicy AllSigned. Keep this file ASCII only.

$ErrorActionPreference = 'Stop'
$AddonVersion = '1.3.3'
$Bin = $PSScriptRoot
$AgentRoot = Split-Path (Split-Path $Bin -Parent) -Parent
$LogFile = Join-Path $AgentRoot 'active-response\active-responses.log'
$StateDir = Join-Path $AgentRoot 'active-response\mamorai'
$IsoState = Join-Path $StateDir 'isolation.json'
$Group = 'MamorAI'
$IsoGroup = 'MamorAI-ISOLATE'
$CriticalServices = @('WazuhSvc','OssecSvc','Tailscale','RpcSs','RpcEptMapper','DcomLaunch','EventLog','Winmgmt','MpsSvc','BFE','Dnscache','LSM','SamSs','Netlogon','NlaSvc','nsi','Dhcp','CryptSvc','gpsvc','ProfSvc','Schedule','TermService')

function Write-Result([string]$Id, [string]$Op, [bool]$Ok, [string]$Detail, [hashtable]$Extra) {
  $o = [ordered]@{ id = $Id; op = $Op; ok = $Ok; detail = ($Detail -replace '\s+', ' ').Trim(); version = $AddonVersion; host = $env:COMPUTERNAME }
  if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
  if ($o.detail.Length -gt 1500) { $o.detail = $o.detail.Substring(0, 1500) }
  $line = 'mamorai-ar: ' + (ConvertTo-Json -InputObject @{ mamorai_ar = $o } -Compress -Depth 4) + "`r`n"
  $enc = New-Object System.Text.UTF8Encoding($false)
  for ($i = 0; $i -lt 5; $i++) { try { [System.IO.File]::AppendAllText($LogFile, $line, $enc); break } catch { Start-Sleep -Milliseconds 300 } }
}

function Get-ManagerIPs {
  $conf = Join-Path $AgentRoot 'ossec.conf'
  $ips = New-Object System.Collections.Generic.List[string]
  try {
    [xml]$x = '<root>' + ((Get-Content -LiteralPath $conf -Raw) -replace '<\?xml[^>]*\?>', '') + '</root>'
    foreach ($n in $x.SelectNodes('//client/server/address')) {
      $a = $n.InnerText.Trim()
      if ($a) { try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($a)) { $ips.Add($ip.IPAddressToString) } } catch { } }
    }
  } catch { }
  return @($ips | Select-Object -Unique)
}

function Get-DcIPs {
  $ips = New-Object System.Collections.Generic.List[string]
  try {
    $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
    foreach ($dc in $d.DomainControllers) { try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($dc.Name)) { $ips.Add($ip.IPAddressToString) } } catch { } }
  } catch { }
  return @($ips | Select-Object -Unique)
}

function Get-DnsIPs { try { return @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique) } catch { return @() } }

function Test-Manager([string[]]$Ips, [int]$Seconds) {
  $until = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $until) {
    foreach ($ip in $Ips) {
      $c = New-Object System.Net.Sockets.TcpClient
      try { $r = $c.BeginConnect($ip, 1514, $null, $null); if ($r.AsyncWaitHandle.WaitOne(3000) -and $c.Connected) { $c.Close(); return $true } } catch { } finally { $c.Close() }
    }
    Start-Sleep -Seconds 3
  }
  return $false
}

function Assert-Ip([string]$Ip) {
  $p = $null
  if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$p)) { throw "invalid IP address" }
  $protected = @(Get-ManagerIPs) + @(Get-DcIPs) + @('127.0.0.1', '::1')
  if ($protected -contains $p.IPAddressToString) { throw "refused: $Ip is the Wazuh manager, a domain controller or loopback" }
  if ($p.IPAddressToString -match '^(127\.|169\.254\.)') { throw "refused: loopback / link-local" }
  return $p.IPAddressToString
}

function Remove-Ref([string]$Ref) {
  $rules = @(Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "MamorAI-$Ref-*" })
  foreach ($r in $rules) { Remove-NetFirewallRule -Name $r.Name }
  return $rules.Count
}

function Invoke-Isolate([bool]$AllowDns, [bool]$AllowAd) {
  if (Test-Path -LiteralPath $IsoState) { return 'already isolated' }
  $mgr = @(Get-ManagerIPs)
  if (-not $mgr.Count) { throw 'refused: no Wazuh manager address found in ossec.conf (the endpoint would be lost)' }
  if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir | Out-Null }
  $profiles = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [string]$_.Enabled; inbound = [string]$_.DefaultInboundAction; outbound = [string]$_.DefaultOutboundAction } })
  $enabled = @(Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Where-Object { $_.Group -ne $IsoGroup -and $_.Group -ne $Group } | ForEach-Object { $_.Name })
  $state = [ordered]@{ at = (Get-Date).ToString('o'); profiles = $profiles; disabled_rules = $enabled; allow_dns = $AllowDns; allow_ad = $AllowAd }
  [System.IO.File]::WriteAllText($IsoState, (ConvertTo-Json -InputObject $state -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
  New-NetFirewallRule -Name 'MamorAI-ISO-mgr' -DisplayName 'MamorAI isolation: Wazuh manager' -Group $IsoGroup -Direction Outbound -Action Allow -Protocol TCP -RemotePort 1514,1515 -RemoteAddress $mgr -Profile Any | Out-Null
  $ts = Get-TailscaledPath
  if ($ts) {
    New-NetFirewallRule -Name 'MamorAI-ISO-ts-out' -DisplayName 'MamorAI isolation: Tailscale (path to the manager)' -Group $IsoGroup -Direction Outbound -Action Allow -Program $ts -Profile Any | Out-Null
    New-NetFirewallRule -Name 'MamorAI-ISO-ts-in' -DisplayName 'MamorAI isolation: Tailscale (path to the manager)' -Group $IsoGroup -Direction Inbound -Action Allow -Program $ts -Profile Any | Out-Null
  }
  if ($AllowDns) { $dns = @(Get-DnsIPs); if ($dns.Count) { New-NetFirewallRule -Name 'MamorAI-ISO-dns-u' -DisplayName 'MamorAI isolation: DNS' -Group $IsoGroup -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -RemoteAddress $dns -Profile Any | Out-Null; New-NetFirewallRule -Name 'MamorAI-ISO-dns-t' -DisplayName 'MamorAI isolation: DNS' -Group $IsoGroup -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 -RemoteAddress $dns -Profile Any | Out-Null } }
  if ($AllowAd) { $dcs = @(Get-DcIPs); if ($dcs.Count) { New-NetFirewallRule -Name 'MamorAI-ISO-ad' -DisplayName 'MamorAI isolation: domain controllers' -Group $IsoGroup -Direction Outbound -Action Allow -RemoteAddress $dcs -Profile Any | Out-Null } }
  if ($enabled.Count) { Disable-NetFirewallRule -Name $enabled -ErrorAction SilentlyContinue }
  Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
  # safety check: the endpoint must still reach the manager, otherwise undo at once (it could never be released remotely)
  if (-not (Test-Manager -Ips $mgr -Seconds 60)) { Invoke-Unisolate | Out-Null; throw 'the Wazuh manager was not reachable after isolation; the isolation was undone' }
  return "isolated; kept: manager $($mgr -join ','), tailscale=$([bool]$ts), dns=$AllowDns, ad=$AllowAd; disabled rules: $($enabled.Count)"
}

function Invoke-Unisolate {
  $msg = ''
  if (Test-Path -LiteralPath $IsoState) {
    $s = Get-Content -LiteralPath $IsoState -Raw | ConvertFrom-Json
    foreach ($p in $s.profiles) { Set-NetFirewallProfile -Name $p.name -Enabled $p.enabled -DefaultInboundAction $p.inbound -DefaultOutboundAction $p.outbound }
    $names = @($s.disabled_rules)
    if ($names.Count) { Enable-NetFirewallRule -Name $names -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $IsoState -Force
    $msg = "restored $($names.Count) rules and the profile defaults"
  } else {
    Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
    $msg = 'no saved state; set Windows defaults (inbound block, outbound allow)'
  }
  Get-NetFirewallRule -Group $IsoGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  return "unisolated; $msg"
}

# Tailscale's daemon path. The Wazuh agent is 32-bit, so this script runs under WOW64 where $env:ProgramFiles is
# 'Program Files (x86)'; look at the service registration first, then the 64-bit Program Files (EDR-130 fix, 1.1.1).
function Get-TailscaledPath {
  $c = @()
  try { $ip = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tailscale' -Name ImagePath -ErrorAction Stop).ImagePath; if ($ip -match '^\s*"?([^"]+?tailscaled\.exe)') { $c += $Matches[1] } } catch { }
  if ($env:ProgramW6432) { $c += (Join-Path $env:ProgramW6432 'Tailscale\tailscaled.exe') }
  $c += (Join-Path $env:ProgramFiles 'Tailscale\tailscaled.exe')
  foreach ($p in $c) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
  return $null
}

# ---------------- Windows Update / winget (EDR-168, 1.2.0) ----------------
$JobDir = Join-Path $StateDir 'jobs'
$UpdLock = Join-Path $StateDir 'update.lock'

function Cut([string]$s, [int]$n) { if ($s.Length -gt $n) { return $s.Substring(0, $n) } return $s }

function Test-RebootPending {
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { return $true }
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { return $true }
  try { $v = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations; if ($v) { return $true } } catch { }
  return $false
}

function Get-WsusServer {
  try { $p = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction Stop; $au = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue; if ($p.WUServer -and $au -and $au.UseWUServer -eq 1) { return [string]$p.WUServer } } catch { }
  return ''
}

function Get-BootTime { try { return (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') } catch { return '' } }

function Get-UpdateCategories($u) { $c = @(); foreach ($x in $u.Categories) { $c += [string]$x.Name }; return $c }

# security = MSRC-rated updates + Security / Critical / Definition updates; never feature upgrades, never previews
function Test-SecurityUpdate($u) {
  $cats = Get-UpdateCategories $u
  if ([string]$u.Title -match 'Preview') { return $false }
  if ([string]$u.MsrcSeverity) { return $true }
  foreach ($c in $cats) { if ($c -in @('Security Updates', 'Critical Updates', 'Definition Updates')) { return $true } }
  return $false
}

function Find-WindowsUpdates {
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'MamorAI'
  $searcher = $session.CreateUpdateSearcher()
  $res = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $list = @()
  foreach ($u in $res.Updates) {
    $cats = Get-UpdateCategories $u
    if ($cats -contains 'Upgrades') { continue }  # whole-OS feature upgrades are out of scope
    $list += $u
  }
  return @{ session = $session; updates = $list }
}

function Format-Update($u) {
  $kb = ''; foreach ($k in $u.KBArticleIDs) { $kb = 'KB' + $k; break }
  $sev = [string]$u.MsrcSeverity; if (-not $sev) { $sev = '-' }
  $cats = (Get-UpdateCategories $u) -join '/'
  $cves = @($u.CveIDs).Count
  $sec = if (Test-SecurityUpdate $u) { 'sec' } else { 'other' }
  $mb = [int]([double]$u.MaxDownloadSize / 1MB)
  $t = (Cut ([string]$u.Title -replace '[|;]', ' ') 110)
  return "$kb|$sev|$sec|$cats|cve:$cves|mb:$mb|$t"
}

function Get-WingetPath {
  $roots = @()
  if ($env:ProgramW6432) { $roots += (Join-Path $env:ProgramW6432 'WindowsApps') }
  $roots += 'C:\Program Files\WindowsApps'
  foreach ($r in $roots) {
    $d = Get-ChildItem -LiteralPath $r -Filter 'Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe' -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if ($d) { $w = Join-Path $d.FullName 'winget.exe'; if (Test-Path -LiteralPath $w) { return $w } }
  }
  return $null
}

function Invoke-Winget([string[]]$WArgs, [int]$TimeoutSec = 900) {
  $w = Get-WingetPath
  if (-not $w) { throw 'winget is not available on this PC (App Installer missing, or Windows Server 2019 or older)' }
  $out = Join-Path $StateDir ('winget-' + [guid]::NewGuid().ToString('N') + '.txt')
  $p = Start-Process -FilePath $w -ArgumentList $WArgs -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError "$out.err"
  if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; throw "winget timed out after $TimeoutSec s" }
  $text = ''
  try { $text = [System.IO.File]::ReadAllText($out, [System.Text.Encoding]::UTF8) } catch { }
  Remove-Item -LiteralPath $out, "$out.err" -Force -ErrorAction SilentlyContinue
  return @{ code = $p.ExitCode; text = $text }
}

# parse "winget upgrade" table from the right: <name...> <id> <version> <available> <source>; works in any UI language
# 1.3.2: the Wazuh agent must never be newer than the manager (a newer agent cannot connect) - it is upgraded only with
# the MamorAI agent pack, which matches the manager version. Hidden from scans and skipped on install.
$ProtectedApps = @('Wazuh.WazuhAgent')
function Get-WingetUpgrades {
  $r = Invoke-Winget @('upgrade', '--include-unknown', '--accept-source-agreements', '--disable-interactivity') 300
  $apps = @(); $inTable = $false
  foreach ($raw in ($r.text -split "`r?`n")) {
    $line = ($raw -replace '^.*\r', '').TrimEnd()
    if ($line -match '^-{10,}') { $inTable = $true; continue }
    if (-not $inTable -or -not $line) { continue }
    if ($line -match '^\d+ ') { $inTable = $false; continue }
    $tok = @($line -split '\s+' | Where-Object { $_ })
    if ($tok.Count -lt 5) { continue }
    $src = $tok[-1]; if ($src -notin @('winget', 'msstore')) { continue }
    $ver = $tok[-3]; $k = 4
    if ($tok[-4] -eq '<' -and $tok.Count -ge 6) { $ver = '<' + $tok[-3]; $k = 5 }  # unknown installed version, shown as "< x.y"
    $id = $tok[-$k]; if ($id -notmatch '^[\w.+-]{2,100}$') { continue }
    if ($ProtectedApps -contains $id) { continue }   # 1.3.2: never through winget (see $ProtectedApps)
    $apps += [ordered]@{ id = $id; name = (Cut (($tok[0..($tok.Count - $k - 1)] -join ' ') -replace '[|;]', ' ') 60); version = $ver; available = $tok[-2] }
  }
  return $apps
}

function Invoke-UpdateScan([bool]$WithApps) {
  $wu = Find-WindowsUpdates
  $lines = @(); $sec = 0
  foreach ($u in $wu.updates) { $lines += (Format-Update $u); if (Test-SecurityUpdate $u) { $sec++ } }
  $appsText = ''; $appCount = 0; $wingetNote = ''
  if ($WithApps) {
    $rec = Get-RecipeUpgrades; $apps = @($rec.apps)
    try { $wg = @(Get-WingetUpgrades); foreach ($w in $wg) { if (-not ($apps | Where-Object { $_.id -eq $w.id }) -and -not ($AppRecipes | Where-Object { $_.id -eq $w.id })) { $w.via = 'winget'; $apps += $w } } }
    catch { $wingetNote = $_.Exception.Message }
    if ($rec.notes.Count) { $wingetNote = (@($wingetNote) + $rec.notes | Where-Object { $_ }) -join ' / ' }
    $appCount = $apps.Count; $appsText = (($apps | Select-Object -First 50 | ForEach-Object { "$($_.id)|$($_.version)|$($_.available)|$($_.name)|$($_.via)" }) -join ' ;; ')
  }
  $ex = @{ phase = 'done'; wu_count = $wu.updates.Count; wu_security = $sec; updates = (Cut (($lines | Select-Object -First 40) -join ' ;; ') 7000); app_count = $appCount; apps = (Cut $appsText 5000); winget = $(if ($wingetNote) { $wingetNote } elseif ($WithApps) { 'ok' } else { 'skipped' }); reboot_pending = (Test-RebootPending); wsus = (Get-WsusServer); boot = (Get-BootTime) }
  return @{ detail = "Windows Update: $($wu.updates.Count) available ($sec security); apps: $appCount; reboot pending: $($ex.reboot_pending)"; extra = $ex }
}

function Assert-Battery {
  $b = $null
  try { $b = Get-CimInstance Win32_Battery -ErrorAction Stop | Select-Object -First 1 } catch { $b = $null }
  if ($b -and $b.BatteryStatus -eq 1 -and $b.EstimatedChargeRemaining -lt 30) { throw "refused: running on battery at $($b.EstimatedChargeRemaining)% (connect the charger and try again)" }
}

function Start-UpdateJob([string]$Id, [string]$Ref, [string]$Wu, [string]$Kb, [string]$Apps) {
  if ($Wu -notin @('security', 'all', 'none', 'kb')) { throw 'invalid --wu' }
  if ($Kb -and $Kb -notmatch '^KB\d{5,8}(,KB\d{5,8}){0,49}$') { throw 'invalid --kb' }
  if ($Apps -and $Apps -notmatch '^(all|none|[\w.+-]{2,100}(,[\w.+-]{2,100}){0,49})$') { throw 'invalid --apps' }
  if ($Wu -eq 'none' -and (-not $Apps -or $Apps -eq 'none')) { throw 'nothing to install' }
  Assert-Battery
  foreach ($d in @($StateDir, $JobDir)) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d | Out-Null } }
  if (Test-Path -LiteralPath $UpdLock) {
    $other = (Get-Content -LiteralPath $UpdLock -Raw).Trim()
    $t = Get-ScheduledTask -TaskName "MamorAI-update-$other" -ErrorAction SilentlyContinue
    if ($t -and $t.State -eq 'Running') { throw "refused: another update ($other) is still running" }
    Remove-Item -LiteralPath $UpdLock -Force
  }
  $jf = Join-Path $JobDir "$Id.json"
  $job = [ordered]@{ id = $Id; ref = $Ref; wu = $Wu; kb = $Kb; apps = $Apps; at = (Get-Date).ToString('o') }
  [System.IO.File]::WriteAllText($jf, (ConvertTo-Json -InputObject $job), (New-Object System.Text.UTF8Encoding($false)))
  [System.IO.File]::WriteAllText($UpdLock, $Id, (New-Object System.Text.UTF8Encoding($false)))
  $ps = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  if ($env:SystemRoot) { $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }  # resolved by the 64-bit Task Scheduler
  $a = New-ScheduledTaskAction -Execute $ps -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File "' + $PSCommandPath + '" -Job "' + $jf + '"')
  $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $st = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName "MamorAI-update-$Id" -Action $a -Principal $pr -Settings $st -Force | Out-Null
  Start-ScheduledTask -TaskName "MamorAI-update-$Id"
  return "update job started (wu=$Wu kb=$Kb apps=$Apps)"
}

# ---------------- 1.3.0: app recipes, progress, cancel, signed-in users, self update ----------------
$ProgressPreference = 'SilentlyContinue'
$DlDir = Join-Path $StateDir 'downloads'

function Compare-Ver([string]$a, [string]$b) {
  $x = @([regex]::Matches($a, '\d+') | ForEach-Object { [long]$_.Value }); $y = @([regex]::Matches($b, '\d+') | ForEach-Object { [long]$_.Value })
  for ($i = 0; $i -lt [Math]::Max($x.Count, $y.Count); $i++) { $p = if ($i -lt $x.Count) { $x[$i] } else { 0 }; $q = if ($i -lt $y.Count) { $y[$i] } else { 0 }; if ($p -ne $q) { return [Math]::Sign($p - $q) } }
  return 0
}

# installed programs for the whole machine (both registry views; this script may run as 32-bit under the Wazuh agent)
function Get-InstalledApps {
  $out = @()
  foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
    try {
      $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
      $k = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
      if (-not $k) { continue }
      foreach ($n in $k.GetSubKeyNames()) {
        $s = $k.OpenSubKey($n); if (-not $s) { continue }
        $dn = [string]$s.GetValue('DisplayName'); $dv = [string]$s.GetValue('DisplayVersion')
        if ($dn -and $dv -and -not $s.GetValue('SystemComponent')) { $out += [pscustomobject]@{ name = $dn; version = $dv; publisher = [string]$s.GetValue('Publisher') } }
      }
    } catch { }
  }
  return $out
}

function Get-EdgeStable {
  $p = Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 -Uri 'https://edgeupdates.microsoft.com/api/products'
  $rel = @(($p | Where-Object { $_.Product -eq 'Stable' }).Releases | Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq 'x64' -and ($_.Artifacts | Where-Object { $_.ArtifactName -eq 'msi' }) })
  $best = $null; foreach ($r in $rel) { if (-not $best -or (Compare-Ver $r.ProductVersion $best.ProductVersion) -gt 0) { $best = $r } }
  if (-not $best) { throw 'no Edge stable x64 MSI found' }
  return @{ version = [string]$best.ProductVersion; url = [string](($best.Artifacts | Where-Object { $_.ArtifactName -eq 'msi' } | Select-Object -First 1).Location) }
}

# vendor recipes: the latest version from the vendor, the vendor's own MSI, and the Authenticode signer it must carry.
# Used before winget because winget (as SYSTEM) often cannot match what is installed (seen with Chrome, 2026-11-06).
$AppRecipes = @(
  @{ id = 'Google.Chrome'; name = 'Google Chrome'; match = '^Google Chrome$'; signer = 'O=Google LLC'
     latest = { [string](Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 -Uri 'https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions?pageSize=1').versions[0].version }
     url = { 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi' } },
  @{ id = 'Microsoft.Edge'; name = 'Microsoft Edge'; match = '^Microsoft Edge$'; signer = 'O=Microsoft Corporation'
     latest = { (Get-EdgeStable).version }; url = { (Get-EdgeStable).url } },
  @{ id = 'Mozilla.Firefox'; name = 'Mozilla Firefox'; match = '^Mozilla Firefox'; signer = 'O=Mozilla Corporation'
     latest = { [string](Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 -Uri 'https://product-details.mozilla.org/1.0/firefox_versions.json').LATEST_FIREFOX_VERSION }
     url = { $l = if ((Get-Culture).Name -like 'ja*') { 'ja' } else { 'en-US' }; "https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=$l" } },
  @{ id = 'Zoom.Zoom'; name = 'Zoom Workplace'; match = '^Zoom( Workplace)?(\s|\(|$)'; signer = 'O="?Zoom (Video )?Communications, Inc\.'
     latest = { [string](Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 -Uri 'https://zoom.us/rest/download?os=win').result.downloadVO.zoom.version }
     url = { 'https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64' } }
)

function Find-RecipeInstalled($r, $apps) { return @($apps | Where-Object { $_.name -match $r.match }) | Sort-Object { $_.version } -Descending | Select-Object -First 1 }

# recipe upgrades that are needed now: id|installed|latest|name|recipe
function Get-RecipeUpgrades {
  $apps = Get-InstalledApps; $out = @(); $notes = @()
  foreach ($r in $AppRecipes) {
    $inst = Find-RecipeInstalled $r $apps; if (-not $inst) { continue }
    try { $latest = & $r.latest } catch { $notes += "$($r.id): latest version unknown ($($_.Exception.Message))"; continue }
    if ($latest -and (Compare-Ver $latest $inst.version) -gt 0) { $out += [ordered]@{ id = $r.id; version = $inst.version; available = $latest; name = $r.name; via = 'recipe' } }
  }
  return @{ apps = $out; notes = $notes }
}

function Invoke-AppRecipe($r) {
  $inst = Find-RecipeInstalled $r (Get-InstalledApps)
  if (-not $inst) { throw "$($r.name) is not installed for the whole machine (per-user installs are not handled)" }
  $latest = & $r.latest
  if ((Compare-Ver $latest $inst.version) -le 0) { return @{ from = $inst.version; to = $inst.version; reboot = $false; note = 'already up to date' } }
  if (-not (Test-Path -LiteralPath $DlDir)) { New-Item -ItemType Directory -Path $DlDir | Out-Null }
  $f = Join-Path $DlDir ($r.id + '-' + ($latest -replace '[^\w.]', '_') + '.msi')
  Invoke-WebRequest -UseBasicParsing -TimeoutSec 900 -Uri (& $r.url) -OutFile $f
  $sig = Get-AuthenticodeSignature -FilePath $f
  if ($sig.Status -ne 'Valid' -or [string]$sig.SignerCertificate.Subject -notmatch $r.signer) {
    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    throw "refused: installer signature $($sig.Status) by '$($sig.SignerCertificate.Subject)' (expected $($r.signer))"
  }
  $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @('/i', ('"' + $f + '"'), '/qn', '/norestart') -Wait -PassThru
  Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
  if ($p.ExitCode -notin @(0, 3010, 1641)) { throw "msiexec exit $($p.ExitCode)" }
  $after = Find-RecipeInstalled $r (Get-InstalledApps)
  return @{ from = $inst.version; to = $(if ($after) { $after.version } else { $latest }); reboot = ($p.ExitCode -in @(3010, 1641)); note = '' }
}

function Format-Items($items) { return (($items.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';') }

# a small background job that reports "still installing (N min)" every 5 minutes while Install() blocks
function Start-Heartbeat([string]$Id, [string]$Ref, [string]$ItemsText) {
  $flag = Join-Path $StateDir "hb-$Id.flag"; Set-Content -LiteralPath $flag -Value '1' -Encoding ASCII
  Start-Job -ArgumentList $LogFile, $Id, $Ref, $AddonVersion, $env:COMPUTERNAME, $flag, $ItemsText -ScriptBlock {
    param($log, $id, $ref, $ver, $hn, $flag, $items)
    $t0 = Get-Date
    while (Test-Path -LiteralPath $flag) {
      Start-Sleep -Seconds 300
      if (-not (Test-Path -LiteralPath $flag)) { break }
      $m = [int]((Get-Date) - $t0).TotalMinutes
      $o = [ordered]@{ id = $id; op = 'update-install'; ok = $true; detail = "installing ($m min)"; version = $ver; host = $hn; ref = $ref; phase = 'progress'; items = $items }
      $line = 'mamorai-ar: ' + (ConvertTo-Json -InputObject @{ mamorai_ar = $o } -Compress) + "`r`n"
      try { [System.IO.File]::AppendAllText($log, $line, (New-Object System.Text.UTF8Encoding($false))) } catch { }
    }
  } | Out-Null
  return $flag
}

function Get-SignedInUsers {
  $u = @()
  $q = Join-Path $env:SystemRoot 'Sysnative\quser.exe'; if (-not (Test-Path -LiteralPath $q)) { $q = Join-Path $env:SystemRoot 'System32\quser.exe' }
  try { $lines = & $q 2>$null; foreach ($l in @($lines | Where-Object { $t = ([string]$_).Trim(); $t -and $t -notmatch '^USERNAME\s' -and $t -notmatch ('^' + (J '\u30e6\u30fc\u30b6\u30fc\u540d') + '\s') })) { $n = ((([string]$l).Trim()) -split '\s+')[0].TrimStart('>'); if ($n) { $u += $n } } } catch { }
  if (-not $u.Count) { try { $x = [string](Get-CimInstance Win32_ComputerSystem).UserName; if ($x) { $u += $x } } catch { } }
  return @($u | Select-Object -Unique)
}

function Stop-UpdateJob {
  if (-not (Test-Path -LiteralPath $UpdLock)) { return 'no update is running' }
  $jid = (Get-Content -LiteralPath $UpdLock -Raw).Trim()
  if ($jid -notmatch '^m[a-z0-9]{1,40}$') { Remove-Item -LiteralPath $UpdLock -Force; return 'removed an invalid lock' }
  try { Stop-ScheduledTask -TaskName "MamorAI-update-$jid" -ErrorAction SilentlyContinue } catch { }
  Start-Sleep -Seconds 3
  try { Unregister-ScheduledTask -TaskName "MamorAI-update-$jid" -Confirm:$false -ErrorAction SilentlyContinue } catch { }
  Remove-Item -LiteralPath (Join-Path $StateDir "hb-$jid.flag"), (Join-Path $JobDir "$jid.json"), $UpdLock -Force -ErrorAction SilentlyContinue
  Write-Result -Id $jid -Op 'update-install' -Ok $false -Detail 'cancelled by MamorAI; Windows may roll back the updates that were being installed and stay busy for a while' -Extra @{ ref = $jid; phase = 'done'; cancelled = $true; reboot_required = (Test-RebootPending) }
  return "update $jid cancelled"
}

# 1.3.0 self update: the manager publishes the signed add-on into the Wazuh group folder; it arrives in <agent>\shared\
function Start-AddonUpdate([string]$Want, [string]$Id) {
  if ($Want -notmatch '^\d+\.\d+\.\d+$') { throw 'invalid version' }
  $sh = Join-Path $AgentRoot 'shared'
  $manP = Join-Path $sh 'mamorai-addon-manifest.json'
  if (-not (Test-Path -LiteralPath $manP)) { throw 'the add-on is not in the shared folder yet (not published by the manager, or the agent has not synced)' }
  $man = Get-Content -LiteralPath $manP -Raw | ConvertFrom-Json
  if ([string]$man.version -ne $Want) { throw "the shared folder has $($man.version), not $Want (wait a few minutes for the agent to sync)" }
  if ((Compare-Ver $Want $AddonVersion) -le 0) { throw "refused: $Want is not newer than $AddonVersion" }
  # the signer is checked from the certificate embedded in the signature (below); Wazuh does not sync binary files such as .cer
  $map = [ordered]@{ 'mamorai-ar.ps1' = 'mamorai-addon-ar.ps1'; 'mamorai-ar.cmd' = 'mamorai-addon-ar.cmd' }
  foreach ($k in $map.Keys) {
    $f = Join-Path $sh $map[$k]; if (-not (Test-Path -LiteralPath $f)) { throw "missing in the shared folder: $($map[$k])" }
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower()
    if ($h -ne [string]$man.files.$k) { throw "refused: $($map[$k]) does not match the manifest" }
  }
  $new = Get-AuthenticodeSignature -FilePath (Join-Path $sh 'mamorai-addon-ar.ps1')
  $cur = Get-AuthenticodeSignature -FilePath $PSCommandPath
  if ($new.Status -ne 'Valid') { throw "refused: the new add-on signature is $($new.Status)" }
  if (-not $cur.SignerCertificate -or $new.SignerCertificate.Thumbprint -ne $cur.SignerCertificate.Thumbprint -or $new.SignerCertificate.Thumbprint -ne [string]$man.signer_thumbprint) { throw 'refused: signed by a different certificate than the installed add-on (a key change needs the agent pack)' }
  $newD = Join-Path $StateDir 'addon-new'; $prevD = Join-Path $StateDir 'addon-prev'
  foreach ($d in @($newD, $prevD)) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d | Out-Null } }
  Copy-Item -LiteralPath (Join-Path $sh 'mamorai-addon-ar.ps1') -Destination (Join-Path $newD 'mamorai-ar.ps1') -Force
  Copy-Item -LiteralPath (Join-Path $sh 'mamorai-addon-ar.cmd') -Destination (Join-Path $newD 'mamorai-ar.cmd') -Force
  Copy-Item -LiteralPath (Join-Path $Bin 'mamorai-ar.ps1') -Destination (Join-Path $prevD 'mamorai-ar.ps1') -Force
  Copy-Item -LiteralPath (Join-Path $Bin 'mamorai-ar.cmd') -Destination (Join-Path $prevD 'mamorai-ar.cmd') -Force
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText((Join-Path $StateDir 'selftest-new.json'), ('{"version":1,"command":"add","parameters":{"extra_args":["version","--id","' + $Id + 'u","--ref","' + $Id + '"]}}'), $enc)
  [System.IO.File]::WriteAllText((Join-Path $StateDir 'selftest-old.json'), ('{"version":1,"command":"add","parameters":{"extra_args":["version","--id","' + $Id + 'r","--ref","' + $Id + '"]}}'), $enc)
  $q = '"'
  $cmd = @(
    '@echo off',
    'ping -n 6 127.0.0.1 >nul',
    "copy /y $q$newD\mamorai-ar.ps1$q $q$Bin\mamorai-ar.ps1$q >nul",
    "copy /y $q$newD\mamorai-ar.cmd$q $q$Bin\mamorai-ar.cmd$q >nul",
    "call $q$Bin\mamorai-ar.cmd$q < $q$StateDir\selftest-new.json$q",
    'if errorlevel 1 (',
    "  copy /y $q$prevD\mamorai-ar.ps1$q $q$Bin\mamorai-ar.ps1$q >nul",
    "  copy /y $q$prevD\mamorai-ar.cmd$q $q$Bin\mamorai-ar.cmd$q >nul",
    "  call $q$Bin\mamorai-ar.cmd$q < $q$StateDir\selftest-old.json$q",
    ') else (',
    "  >$q$Bin\mamorai-ar.version$q echo $Want",
    ')',
    'schtasks /delete /tn MamorAI-addon-update /f >nul 2>&1'
  ) -join "`r`n"
  $cf = Join-Path $StateDir 'addon-update.cmd'
  [System.IO.File]::WriteAllText($cf, $cmd + "`r`n", [System.Text.Encoding]::ASCII)
  $a = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\cmd.exe') -Argument ('/c "' + $cf + '"')
  $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName 'MamorAI-addon-update' -Action $a -Principal $pr -Force | Out-Null
  Start-ScheduledTask -TaskName 'MamorAI-addon-update'
  return "add-on update $AddonVersion -> $Want started (verified hash and signer $($new.SignerCertificate.Thumbprint))"
}

# runs inside the scheduled task
function Invoke-UpdateJob([string]$JobFile) {
  $job = Get-Content -LiteralPath $JobFile -Raw | ConvertFrom-Json
  $id = [string]$job.id; $ref = [string]$job.ref; $op = 'update-install'
  $installed = @(); $failed = @(); $reboot = $false
  try {
    $items = [ordered]@{}
    if ($job.wu -ne 'none') {
      Write-Result -Id $id -Op $op -Ok $true -Detail 'searching Windows Update' -Extra @{ ref = $ref; phase = 'progress' }
      $wu = Find-WindowsUpdates
      $want = @(); $kbs = @(); if ($job.kb) { $kbs = @(([string]$job.kb) -split ',') }
      foreach ($u in $wu.updates) {
        $kb = ''; foreach ($k in $u.KBArticleIDs) { $kb = 'KB' + $k; break }
        if ($job.wu -eq 'kb') { if ($kbs -contains $kb) { $want += $u } }
        elseif ($job.wu -eq 'all' -or (Test-SecurityUpdate $u) -or ($kbs -contains $kb)) { $want += $u }
      }
      foreach ($u in $want) { $items[(Format-Update $u).Split('|')[0]] = 'pending' }
      if ($want.Count) {
        # 1.3.0: download one by one so the card shows which update is being fetched
        $ok2 = New-Object -ComObject Microsoft.Update.UpdateColl; $n = 0
        foreach ($u in $want) {
          $n++; $kb = (Format-Update $u).Split('|')[0]; $mb = [int]([double]$u.MaxDownloadSize / 1MB)
          if (-not $u.EulaAccepted) { $u.AcceptEula() }
          $items[$kb] = 'downloading'
          Write-Result -Id $id -Op $op -Ok $true -Detail "downloading $kb ($n/$($want.Count), up to $mb MB)" -Extra @{ ref = $ref; phase = 'progress'; items = (Format-Items $items) }
          $one = New-Object -ComObject Microsoft.Update.UpdateColl; [void]$one.Add($u)
          $dl = $wu.session.CreateUpdateDownloader(); $dl.Updates = $one; $dr = $dl.Download()
          if ($u.IsDownloaded) { $items[$kb] = 'downloaded'; [void]$ok2.Add($u) } else { $items[$kb] = 'failed'; $failed += ("$kb(download code $($dr.ResultCode))") }
        }
        if ($ok2.Count) {
          foreach ($k in @($items.Keys)) { if ($items[$k] -eq 'downloaded') { $items[$k] = 'installing' } }
          $it = Format-Items $items
          Write-Result -Id $id -Op $op -Ok $true -Detail "installing $($ok2.Count) update(s)" -Extra @{ ref = $ref; phase = 'progress'; items = $it }
          $hb = Start-Heartbeat -Id $id -Ref $ref -ItemsText $it
          try { $ins = $wu.session.CreateUpdateInstaller(); $ins.Updates = $ok2; $r = $ins.Install() }
          finally { Remove-Item -LiteralPath $hb -Force -ErrorAction SilentlyContinue }
          for ($i = 0; $i -lt $ok2.Count; $i++) {
            $u = $ok2.Item($i); $kb = (Format-Update $u).Split('|')[0]; $rc = $r.GetUpdateResult($i).ResultCode
            if ($rc -eq 2 -or $rc -eq 3) { $installed += $kb; $items[$kb] = 'installed' } else { $failed += ("$kb(code $rc, 0x{0:X8})" -f $r.GetUpdateResult($i).HResult); $items[$kb] = 'failed' }
          }
          if ($r.RebootRequired) { $reboot = $true }
        }
      }
    }
    if ($job.apps -and $job.apps -ne 'none') {
      $ids = @()
      if ($job.apps -eq 'all') {
        $ids = @((Get-RecipeUpgrades).apps | ForEach-Object { $_.id })
        try { $ids += @(Get-WingetUpgrades | ForEach-Object { $_.id } | Where-Object { $ids -notcontains $_ }) } catch { }
      } else { $ids = @(([string]$job.apps) -split ',') }
      $ids = @($ids | Where-Object { $ProtectedApps -notcontains $_ })   # 1.3.2: an explicit request is refused too
      foreach ($a in $ids) { $items["app:$a"] = 'pending' }
      foreach ($a in $ids) {
        $items["app:$a"] = 'installing'
        $rec = $AppRecipes | Where-Object { $_.id -eq $a } | Select-Object -First 1
        Write-Result -Id $id -Op $op -Ok $true -Detail $(if ($rec) { "app $a (vendor installer)" } else { "winget upgrade $a" }) -Extra @{ ref = $ref; phase = 'progress'; items = (Format-Items $items) }
        try {
          if ($rec) {
            $x = Invoke-AppRecipe $rec
            $installed += "app:$a"; $items["app:$a"] = 'installed'
            if ($x.reboot) { $reboot = $true }
          } else {
            $w = Invoke-Winget @('upgrade', '--id', $a, '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity') 1200
            if ($w.code -eq 0) { $installed += "app:$a"; $items["app:$a"] = 'installed' } else { $failed += ("app:$a(exit 0x{0:X8})" -f $w.code); $items["app:$a"] = 'failed' }
          }
        } catch { $failed += "app:$a($(($_.Exception.Message) -replace '[,()]', ' '))"; $items["app:$a"] = 'failed' }
      }
    }
    $reboot = $reboot -or (Test-RebootPending)
    $ok = ($failed.Count -eq 0)
    $d = "installed $($installed.Count), failed $($failed.Count), reboot required: $reboot"
    Write-Result -Id $id -Op $op -Ok $ok -Detail $d -Extra @{ ref = $ref; phase = 'done'; installed = (Cut ($installed -join ',') 3000); failed = (Cut ($failed -join ',') 2000); reboot_required = $reboot; items = (Format-Items $items) }
  } catch {
    Write-Result -Id $id -Op $op -Ok $false -Detail $_.Exception.Message -Extra @{ ref = $ref; phase = 'done'; installed = ($installed -join ','); failed = ($failed -join ','); reboot_required = (Test-RebootPending) }
  } finally {
    Remove-Item -LiteralPath $JobFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $UpdLock -Force -ErrorAction SilentlyContinue
    try { Unregister-ScheduledTask -TaskName "MamorAI-update-$id" -Confirm:$false -ErrorAction SilentlyContinue } catch { }
  }
}

# ---------------- 1.3.1: reboot with a Japanese prompt; the signed-in user may postpone (5 min / 1 h / 4 h) ----------------
# Postponing is allowed any number of times, but never past 4 hours after the first notice. No answer = restart as scheduled.
# The SYSTEM task MamorAI-reboot-<id> owns the schedule; the prompt runs as the signed-in user (task MamorAI-rebootui-<id>,
# group Users) from a read-only signed copy in ProgramData\MamorAI\bin and only writes its answer into ProgramData\MamorAI\reboot.
$RebootDir = Join-Path $env:ProgramData 'MamorAI\reboot'
$PromptDir = Join-Path $env:ProgramData 'MamorAI\bin'
$RebootChoices = @(0, 5, 60, 240)
$RebootMaxMin = 240
function J([string]$s) { return [regex]::Unescape($s) }
function NowUnix { return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
function UnixIso([long]$t) { return [DateTimeOffset]::FromUnixTimeSeconds($t).UtcDateTime.ToString('o') }
function UnixLocal([long]$t) { return [DateTimeOffset]::FromUnixTimeSeconds($t).LocalDateTime.ToString('HH:mm') }
function Get-PsExe { if ($env:SystemRoot) { return (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') }; return 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }

function Remove-RebootTasks {
  foreach ($pat in @('MamorAI-rebootui-*', 'MamorAI-reboot-*')) {
    foreach ($t in @(Get-ScheduledTask -TaskName $pat -ErrorAction SilentlyContinue)) {
      try { Stop-ScheduledTask -InputObject $t -ErrorAction SilentlyContinue } catch { }
      try { Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    }
  }
}

function Start-RebootJob([string]$Id, [string]$Ref, [int]$Minutes) {
  Remove-RebootTasks
  foreach ($d in @($StateDir, $JobDir, $RebootDir, $PromptDir)) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
  $ic = Join-Path $env:SystemRoot 'System32\icacls.exe'
  # answers: Users may create/modify files here (the SYSTEM task only accepts 0/5/60/240 and the 4 h limit)
  & $ic $RebootDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)M' | Out-Null
  # the prompt script: Users may only read/run it (signed; started with -ExecutionPolicy AllSigned)
  Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $PromptDir 'mamorai-ar.ps1') -Force
  & $ic $PromptDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
  Get-ChildItem -LiteralPath $RebootDir -Filter 'choice-*.txt' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
  $now = NowUnix
  $job = [ordered]@{ id = $Id; ref = $Ref; due = ($now + $Minutes * 60); max = ($now + $RebootMaxMin * 60) }
  $jf = Join-Path $JobDir "reboot-$Id.json"
  [System.IO.File]::WriteAllText($jf, (ConvertTo-Json -InputObject $job), (New-Object System.Text.UTF8Encoding($false)))
  $a = New-ScheduledTaskAction -Execute (Get-PsExe) -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File "' + $PSCommandPath + '" -RebootJob "' + $jf + '"')
  $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $st = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName "MamorAI-reboot-$Id" -Action $a -Principal $pr -Settings $st -Force | Out-Null
  Start-ScheduledTask -TaskName "MamorAI-reboot-$Id"
  return $job
}

function Show-RebootPromptTask([string]$Id, [long]$Due, [long]$Max) {
  $tn = "MamorAI-rebootui-$Id"
  try { Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue } catch { }
  $a = New-ScheduledTaskAction -Execute (Get-PsExe) -Argument ('-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy AllSigned -File "' + (Join-Path $PromptDir 'mamorai-ar.ps1') + '" -RebootPrompt ' + $Id + ' ' + $Due + ' ' + $Max)
  $pr = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
  $st = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances Parallel
  Register-ScheduledTask -TaskName $tn -Action $a -Principal $pr -Settings $st -Force | Out-Null
  Start-ScheduledTask -TaskName $tn
}

# runs inside the SYSTEM task
function Invoke-RebootJob([string]$JobFile) {
  $job = Get-Content -LiteralPath $JobFile -Raw | ConvertFrom-Json
  $id = [string]$job.id; $ref = [string]$job.ref; $due = [long]$job.due; $max = [long]$job.max
  $choice = Join-Path $RebootDir "choice-$id.txt"
  try {
    Show-RebootPromptTask -Id $id -Due $due -Max $max
    $asked = $due
    while ($true) {
      $now = NowUnix
      if (Test-Path -LiteralPath $choice) {
        $raw = ''; try { $raw = ([string](Get-Content -LiteralPath $choice -Raw)).Trim() } catch { }
        Remove-Item -LiteralPath $choice -Force -ErrorAction SilentlyContinue
        $v = -1
        if ([int]::TryParse($raw, [ref]$v) -and $RebootChoices -contains $v) {
          $due = [math]::Min($now + $v * 60, $max)
          if ($v -eq 0) {
            Write-Result -Id $id -Op 'reboot' -Ok $true -Detail 'the signed-in user chose to restart now' -Extra @{ ref = $ref; phase = 'postponed'; minutes = 0; at = (UnixIso $due) }
          } else {
            Write-Result -Id $id -Op 'reboot' -Ok $true -Detail "the signed-in user postponed the restart by $v min (restart at $(UnixLocal $due) local time)" -Extra @{ ref = $ref; phase = 'postponed'; minutes = $v; at = (UnixIso $due); max = (UnixIso $max) }
            $asked = 0   # ask again shortly before the new time
          }
        }
      }
      if ($now -ge $due) { break }
      if ($asked -ne $due -and ($due - $now) -le 120 -and @(Get-SignedInUsers).Count) { Show-RebootPromptTask -Id $id -Due $due -Max $max; $asked = $due }
      Start-Sleep -Seconds 5
    }
    try { Stop-ScheduledTask -TaskName "MamorAI-rebootui-$id" -ErrorAction SilentlyContinue } catch { }
    try { Unregister-ScheduledTask -TaskName "MamorAI-rebootui-$id" -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    $msg = J 'MamorAI: \u66f4\u65b0\u3092\u5b8c\u4e86\u3059\u308b\u305f\u3081\u30011\u5206\u5f8c\u306b\u3053\u306ePC\u3092\u518d\u8d77\u52d5\u3057\u307e\u3059\u3002\u4f5c\u696d\u3092\u4fdd\u5b58\u3057\u3066\u304f\u3060\u3055\u3044\u3002'
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\shutdown.exe') -ArgumentList @('/r', '/t', '60', '/c', ('"' + $msg + '"'), '/d', 'p:2:17') -NoNewWindow -Wait -PassThru
    Write-Result -Id $id -Op 'reboot' -Ok ($p.ExitCode -eq 0) -Detail $(if ($p.ExitCode -eq 0) { 'restarting in 1 minute' } else { "shutdown.exe failed (exit $($p.ExitCode))" }) -Extra @{ ref = $ref; phase = 'rebooting'; at = (UnixIso ((NowUnix) + 60)) }
  } catch {
    Write-Result -Id $id -Op 'reboot' -Ok $false -Detail $_.Exception.Message -Extra @{ ref = $ref; phase = 'failed' }
  } finally {
    Remove-Item -LiteralPath $JobFile, $choice -Force -ErrorAction SilentlyContinue
    try { Unregister-ScheduledTask -TaskName "MamorAI-reboot-$id" -Confirm:$false -ErrorAction SilentlyContinue } catch { }
  }
}

function Stop-RebootJob {
  $had = @(Get-ScheduledTask -TaskName 'MamorAI-reboot-*' -ErrorAction SilentlyContinue).Count
  Remove-RebootTasks
  Get-ChildItem -LiteralPath $JobDir -Filter 'reboot-*.json' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
  $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\shutdown.exe') -ArgumentList @('/a') -NoNewWindow -Wait -PassThru
  if ($had -or $p.ExitCode -eq 0) { return 'scheduled restart cancelled' }
  return "no scheduled restart to cancel (exit $($p.ExitCode))"
}

# runs as the signed-in user: a small topmost Japanese dialog with a countdown
function Show-RebootDialog([string]$Id, [long]$Due, [long]$Max) {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  $script:rdId = $Id; $script:rdDue = $Due; $script:rdMax = $Max
  $f = New-Object System.Windows.Forms.Form
  $f.Text = J 'MamorAI - \u518d\u8d77\u52d5\u306e\u304a\u77e5\u3089\u305b'
  $f.StartPosition = 'CenterScreen'; $f.TopMost = $true; $f.FormBorderStyle = 'FixedDialog'; $f.ControlBox = $false
  $f.ClientSize = New-Object System.Drawing.Size(520, 230); $f.Font = New-Object System.Drawing.Font('Yu Gothic UI', 10)
  $l1 = New-Object System.Windows.Forms.Label
  $l1.Text = J '\u66f4\u65b0\u30d7\u30ed\u30b0\u30e9\u30e0\u306e\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb\u3092\u5b8c\u4e86\u3059\u308b\u305f\u3081\u3001\u3053\u306ePC\u3092\u518d\u8d77\u52d5\u3057\u307e\u3059\u3002\u4f5c\u696d\u4e2d\u306e\u30d5\u30a1\u30a4\u30eb\u3092\u4fdd\u5b58\u3057\u3066\u304f\u3060\u3055\u3044\u3002'
  $l1.SetBounds(16, 12, 488, 48)
  $script:rdL2 = New-Object System.Windows.Forms.Label
  $script:rdL2.Font = New-Object System.Drawing.Font('Yu Gothic UI', 13, [System.Drawing.FontStyle]::Bold); $script:rdL2.SetBounds(16, 64, 488, 30)
  $l3 = New-Object System.Windows.Forms.Label
  $l3.Text = [string]::Format((J '\u5ef6\u671f\u3067\u304d\u308b\u306e\u306f {0} \u307e\u3067\u3067\u3059\u3002\u4f55\u3082\u9078\u3070\u306a\u3044\u3068\u4e88\u5b9a\u3069\u304a\u308a\u518d\u8d77\u52d5\u3057\u307e\u3059\u3002'), (UnixLocal $Max))
  $l3.ForeColor = [System.Drawing.Color]::DimGray; $l3.SetBounds(16, 98, 488, 40)
  $f.Controls.AddRange(@($l1, $script:rdL2, $l3))
  $labels = @((J '\u4eca\u3059\u3050\u518d\u8d77\u52d5'), (J '5\u5206\u5f8c'), (J '1\u6642\u9593\u5f8c'), (J '4\u6642\u9593\u5f8c'))
  $script:rdButtons = @()
  for ($i = 0; $i -lt 4; $i++) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $labels[$i]; $b.Tag = $RebootChoices[$i]; $b.SetBounds((16 + $i * 124), 160, 116, 44)
    $b.Add_Click({
      param($s, $e)
      try { [System.IO.File]::WriteAllText((Join-Path $RebootDir ('choice-' + $script:rdId + '.txt')), [string]$s.Tag, (New-Object System.Text.UTF8Encoding($false))) } catch { }
      $s.FindForm().Close()
    })
    $f.Controls.Add($b); $script:rdButtons += $b
  }
  $script:rdForm = $f
  $tick = {
    $left = $script:rdDue - (NowUnix)
    if ($left -le 0) { $script:rdForm.Close(); return }
    $txt = $(if ($left -ge 3600) { [string]::Format((J '{0}\u6642\u9593{1:00}\u5206'), [math]::Floor($left / 3600), [math]::Floor(($left % 3600) / 60)) } else { [string]::Format((J '{0}\u5206{1:00}\u79d2'), [math]::Floor($left / 60), ($left % 60)) })
    $script:rdL2.Text = [string]::Format((J '\u518d\u8d77\u52d5\u307e\u3067 \u3042\u3068 {0}\uff08{1} \u306e\u4e88\u5b9a\uff09'), $txt, (UnixLocal $script:rdDue))
    foreach ($b in $script:rdButtons) { if ([int]$b.Tag -gt 0) { $b.Enabled = ((NowUnix) + [int]$b.Tag * 60) -le $script:rdMax } }
  }
  & $tick
  $tm = New-Object System.Windows.Forms.Timer; $tm.Interval = 1000; $tm.Add_Tick($tick); $tm.Start()
  [void]$f.ShowDialog()
  $tm.Stop()
}

# ---------------- 1.3.3 (EDR-171): update the agent pack remotely ----------------
# The manager publishes the Windows pack without secrets into the agent group folder (installer/windows/publish-pack.sh):
# mamorai-pack-{Install-EdrAgent.ps1,Install-MamoraiAddon.ps1,config.json,pack.json,manifest.json}. "pack-update <rev>"
# checks the hashes and that both scripts are signed by the same certificate as this add-on, stages a pack folder and
# runs "Install-EdrAgent.ps1 -Mode update -Unattended" in a one-shot SYSTEM task (it restarts the Wazuh agent).
function Get-ManifestValue($obj, [string]$key) { $p = $obj.PSObject.Properties[$key]; if ($p) { return [string]$p.Value } return '' }
function Start-PackUpdate([string]$Rev, [string]$Id, [string]$Ref) {
  if ($Rev -notmatch '^\d{1,6}$') { throw 'invalid pack revision' }
  $sh = Join-Path $AgentRoot 'shared'
  $manP = Join-Path $sh 'mamorai-pack-manifest.json'
  if (-not (Test-Path -LiteralPath $manP)) { throw 'the pack is not in the shared folder yet (not published by the manager, or the agent has not synced)' }
  $man = Get-Content -LiteralPath $manP -Raw | ConvertFrom-Json
  if ([string]$man.rev -ne $Rev) { throw "the shared folder has pack r$($man.rev), not r$Rev (wait a few minutes for the agent to sync)" }
  $cur = Get-AuthenticodeSignature -FilePath $PSCommandPath
  if (-not $cur.SignerCertificate) { throw 'this add-on is not signed' }
  $map = [ordered]@{ 'Install-EdrAgent.ps1' = 'mamorai-pack-Install-EdrAgent.ps1'; 'Install-MamoraiAddon.ps1' = 'mamorai-pack-Install-MamoraiAddon.ps1'; 'config.json' = 'mamorai-pack-config.json'; 'pack.json' = 'mamorai-pack-pack.json' }
  foreach ($k in $map.Keys) {
    $f = Join-Path $sh $map[$k]; if (-not (Test-Path -LiteralPath $f)) { throw "missing in the shared folder: $($map[$k])" }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower() -ne (Get-ManifestValue $man.files $k)) { throw "refused: $($map[$k]) does not match the pack manifest" }
  }
  foreach ($k in @('Install-EdrAgent.ps1', 'Install-MamoraiAddon.ps1')) {
    $sig = Get-AuthenticodeSignature -FilePath (Join-Path $sh $map[$k])
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $cur.SignerCertificate.Thumbprint -or $sig.SignerCertificate.Thumbprint -ne [string]$man.signer_thumbprint) { throw "refused: $k is not signed by the certificate of the installed add-on ($($sig.Status))" }
  }
  # the add-on that goes with the pack (published next to it): checked against its own manifest
  $am = Join-Path $sh 'mamorai-addon-manifest.json'
  if (-not (Test-Path -LiteralPath $am)) { throw 'the add-on is missing in the shared folder' }
  $aman = Get-Content -LiteralPath $am -Raw | ConvertFrom-Json
  foreach ($k in @('mamorai-ar.ps1', 'mamorai-ar.cmd')) {
    $f = Join-Path $sh ('mamorai-addon-' + $k.Substring(8)); if (-not (Test-Path -LiteralPath $f)) { throw "missing in the shared folder: $(Split-Path $f -Leaf)" }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower() -ne (Get-ManifestValue $aman.files $k)) { throw "refused: $(Split-Path $f -Leaf) does not match the add-on manifest" }
  }
  foreach ($t in @(Get-ScheduledTask -TaskName 'MamorAI-pack-*' -ErrorAction SilentlyContinue)) { if ($t.State -eq 'Running') { throw 'refused: a pack update is already running' } }
  if (Test-Path -LiteralPath $UpdLock) { throw 'refused: Windows updates are running on this PC (try again when they are done)' }
  $d = Join-Path $StateDir "pack-r$Rev"
  if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
  New-Item -ItemType Directory -Path (Join-Path $d 'addon') -Force | Out-Null
  if (-not (Test-Path -LiteralPath $JobDir)) { New-Item -ItemType Directory -Path $JobDir -Force | Out-Null }
  Copy-Item -LiteralPath (Join-Path $sh $map['Install-EdrAgent.ps1']) -Destination (Join-Path $d 'Install-EdrAgent.ps1') -Force
  Copy-Item -LiteralPath (Join-Path $sh $map['config.json']) -Destination (Join-Path $d 'config.json') -Force
  Copy-Item -LiteralPath (Join-Path $sh $map['pack.json']) -Destination (Join-Path $d 'pack.json') -Force
  Copy-Item -LiteralPath (Join-Path $sh $map['Install-MamoraiAddon.ps1']) -Destination (Join-Path $d 'addon\Install-MamoraiAddon.ps1') -Force
  Copy-Item -LiteralPath (Join-Path $sh 'mamorai-addon-ar.ps1') -Destination (Join-Path $d 'addon\mamorai-ar.ps1') -Force
  Copy-Item -LiteralPath (Join-Path $sh 'mamorai-addon-ar.cmd') -Destination (Join-Path $d 'addon\mamorai-ar.cmd') -Force
  Copy-Item -LiteralPath $am -Destination (Join-Path $d 'addon\manifest.json') -Force
  # Wazuh does not sync binary files: the certificate comes from the signature itself (same DER bytes as the .cer)
  $newSig = Get-AuthenticodeSignature -FilePath (Join-Path $d 'addon\mamorai-ar.ps1')
  if ($newSig.Status -ne 'Valid' -or $newSig.SignerCertificate.Thumbprint -ne $cur.SignerCertificate.Thumbprint) { throw "refused: the add-on in the shared folder is not signed by the same certificate ($($newSig.Status))" }
  [System.IO.File]::WriteAllBytes((Join-Path $d 'addon\mamorai-addon-signing.cer'), $newSig.SignerCertificate.RawData)
  $jf = Join-Path $JobDir "pack-$Id.json"
  [System.IO.File]::WriteAllText($jf, (ConvertTo-Json -InputObject ([ordered]@{ id = $Id; ref = $Ref; rev = $Rev; dir = $d })), (New-Object System.Text.UTF8Encoding($false)))
  $a = New-ScheduledTaskAction -Execute (Get-PsExe) -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File "' + $PSCommandPath + '" -PackJob "' + $jf + '"')
  $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $st = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName "MamorAI-pack-$Id" -Action $a -Principal $pr -Settings $st -Force | Out-Null
  Start-ScheduledTask -TaskName "MamorAI-pack-$Id"
  return "pack update to r$Rev started (verified hashes and signer $($cur.SignerCertificate.Thumbprint))"
}

# runs inside the SYSTEM task; the pack installer restarts WazuhSvc, so the result line is sent after it reconnects
function Invoke-PackJob([string]$JobFile) {
  $job = Get-Content -LiteralPath $JobFile -Raw | ConvertFrom-Json
  $id = [string]$job.id; $ref = [string]$job.ref; $rev = [string]$job.rev; $d = [string]$job.dir
  $log = Join-Path $env:ProgramData 'MamorAI\agent-install.log'
  $mark = 0; if (Test-Path -LiteralPath $log) { $mark = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue).Count }
  try {
    Write-Result -Id $id -Op 'pack-update' -Ok $true -Detail "running the pack installer r$rev (the Wazuh agent restarts at the end)" -Extra @{ ref = $ref; phase = 'progress'; rev = $rev }
    $inst = Join-Path $d 'Install-EdrAgent.ps1'
    $p = Start-Process -FilePath (Get-PsExe) -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'AllSigned', '-File', ('"' + $inst + '"'), '-sourceDir', ('"' + $d + '"'), '-Mode', 'update', '-Unattended', '-KeepFiles') -WindowStyle Hidden -PassThru
    if (-not $p.WaitForExit(50 * 60 * 1000)) { try { $p.Kill() } catch { }; throw 'the pack installer did not finish within 50 minutes' }
    $rc = $p.ExitCode
    $tail = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Select-Object -Skip $mark | Where-Object { $_ -match '\[(OK|WARN|ERROR|STEP)\]' } | Select-Object -Last 6) -join ' | '
    Start-Sleep -Seconds 20   # give the restarted agent time to reconnect before the result line is written
    Write-Result -Id $id -Op 'pack-update' -Ok ($rc -eq 0) -Detail ((Cut $tail 1200) -replace '\s+', ' ') -Extra @{ ref = $ref; phase = 'done'; rev = $rev; rc = $rc }
  } catch {
    Write-Result -Id $id -Op 'pack-update' -Ok $false -Detail $_.Exception.Message -Extra @{ ref = $ref; phase = 'done'; rev = $rev }
  } finally {
    Remove-Item -LiteralPath $JobFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
    try { Unregister-ScheduledTask -TaskName "MamorAI-pack-$id" -Confirm:$false -ErrorAction SilentlyContinue } catch { }
  }
}

# ---------------- main ----------------
if ($args.Count -ge 4 -and $args[0] -eq '-RebootPrompt') {
  $rid = [string]$args[1]; $d = 0L; $mx = 0L
  if ($rid -notmatch '^m[a-z0-9]{1,40}$' -or -not [long]::TryParse([string]$args[2], [ref]$d) -or -not [long]::TryParse([string]$args[3], [ref]$mx)) { exit 2 }
  Show-RebootDialog -Id $rid -Due $d -Max $mx
  exit 0
}
if ($args.Count -ge 2 -and $args[0] -eq '-PackJob') {
  $jf = [string]$args[1]
  if ($jf -notlike (Join-Path $JobDir 'pack-*.json')) { exit 2 }
  Invoke-PackJob -JobFile $jf
  exit 0
}
if ($args.Count -ge 2 -and $args[0] -eq '-RebootJob') {
  $jf = [string]$args[1]
  if ($jf -notlike (Join-Path $JobDir 'reboot-*.json')) { exit 2 }
  Invoke-RebootJob -JobFile $jf
  exit 0
}
if ($args.Count -ge 2 -and $args[0] -eq '-Job') {
  $jf = [string]$args[1]
  if ($jf -notlike (Join-Path $JobDir '*.json')) { exit 2 }
  Invoke-UpdateJob -JobFile $jf
  exit 0
}
$id = 'unknown'; $op = 'unknown'; $script:packRev = ''; $script:verExtra = $null; $script:opExtra = $null
try {
  $line = [Console]::In.ReadLine()
  if (-not $line) { throw 'no input (this script is started by the Wazuh agent)' }
  $msg = $line | ConvertFrom-Json
  if ($msg.command -and $msg.command -ne 'add') { exit 0 }
  $argv = @($msg.parameters.extra_args | ForEach-Object { [string]$_ })
  if (-not $argv.Count) { throw 'no operation' }
  $op = $argv[0]
  $pos = New-Object System.Collections.Generic.List[string]; $flags = @{}; $ref = $null
  for ($i = 1; $i -lt $argv.Count; $i++) {
    switch -regex ($argv[$i]) {
      '^--id$'  { $id = $argv[++$i]; continue }
      '^--ref$' { $ref = $argv[++$i]; continue }
      '^allow-(dns|ad)$' { $flags[$argv[$i]] = $true; continue }
      '^--(wu|kb|apps|minutes)$' { $k = $argv[$i]; $i++; $flags[$k] = $argv[$i]; continue }  # key first: PowerShell evaluates the right side before the index
      default { $pos.Add($argv[$i]) }
    }
  }
  if ($id -notmatch '^m[a-z0-9]{1,40}$') { $id = 'invalid'; throw 'invalid --id' }
  if ($ref -and $ref -notmatch '^m[a-z0-9]{1,40}$') { throw 'invalid --ref' }
  if (-not $ref) { $ref = $id }
  $detail = ''
  switch ($op) {
    'version' {
      # EDR-130: also report which agent pack revision was installed on this PC (written by Install-EdrAgent.ps1)
      $packRev = ''
      $pj = Join-Path $env:ProgramData 'MamorAI\pack.json'
      if (Test-Path -LiteralPath $pj) { try { $packRev = [string]((Get-Content -LiteralPath $pj -Raw | ConvertFrom-Json).rev) } catch { $packRev = '' } }
      if ($packRev -notmatch '^\d{1,6}$') { $packRev = '' }
      $script:packRev = $packRev
      $detail = "MamorAI add-on $AddonVersion on $env:COMPUTERNAME (PowerShell $($PSVersionTable.PSVersion))" + $(if ($packRev) { " pack r$packRev" } else { '' })
      $script:verExtra = @{ boot = (Get-BootTime); reboot_pending = (Test-RebootPending) }
    }
    'update-scan' { $r = Invoke-UpdateScan -WithApps ([string]$flags['--apps'] -eq 'yes'); $detail = $r.detail; $script:opExtra = $r.extra }
    'update-install' { $detail = Start-UpdateJob -Id $id -Ref $ref -Wu ([string]$flags['--wu']) -Kb ([string]$flags['--kb']) -Apps ([string]$flags['--apps']); $script:opExtra = @{ phase = 'started' } }
    'reboot' {
      $m = 0; if (-not [int]::TryParse([string]$flags['--minutes'], [ref]$m) -or $m -lt 1 -or $m -gt 120) { throw 'invalid --minutes (1-120)' }
      $users = @(Get-SignedInUsers); $who = $users -join ', '
      if ($users.Count) {
        # 1.3.1: someone is signed in -> Japanese prompt; they may postpone (5 min / 1 h / 4 h, up to 4 h in total)
        $j = Start-RebootJob -Id $id -Ref $ref -Minutes $m
        $detail = "restart scheduled in $m minute(s); signed-in user: $who (asked; may postpone up to $RebootMaxMin min)"
        $script:opExtra = @{ phase = 'scheduled'; boot = (Get-BootTime); at = (UnixIso $j.due); max = (UnixIso $j.max); prompt = $true }
      } else {
        $msg = [string]::Format((J 'MamorAI: \u66f4\u65b0\u3092\u5b8c\u4e86\u3059\u308b\u305f\u3081\u3001{0}\u5206\u5f8c\u306b\u3053\u306ePC\u3092\u518d\u8d77\u52d5\u3057\u307e\u3059\u3002\u4f5c\u696d\u3092\u4fdd\u5b58\u3057\u3066\u304f\u3060\u3055\u3044\u3002'), $m)
        $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\shutdown.exe') -ArgumentList @('/r', '/t', [string]($m * 60), '/c', ('"' + $msg + '"'), '/d', 'p:2:17') -NoNewWindow -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "shutdown.exe failed (exit $($p.ExitCode)); a restart may already be scheduled" }
        $detail = "restart scheduled in $m minute(s); no user signed in"
        $script:opExtra = @{ phase = 'scheduled'; boot = (Get-BootTime); at = (Get-Date).ToUniversalTime().AddMinutes($m).ToString('o'); prompt = $false }
      }
    }
    'pack-update' { $detail = Start-PackUpdate -Rev ([string]$pos[0]) -Id $id -Ref $ref; $script:opExtra = @{ phase = 'started'; rev = [string]$pos[0] } }
    'update-cancel' { $detail = Stop-UpdateJob }
    'addon-update' { $detail = Start-AddonUpdate -Want ([string]$pos[0]) -Id $id; $script:opExtra = @{ phase = 'started'; target = [string]$pos[0] } }
    'reboot-cancel' { $detail = Stop-RebootJob }
    'service-stop' {
      $n = $pos[0]; if ($n -notmatch '^[\w.@$ -]{1,128}$') { throw 'invalid service name' }
      if ($CriticalServices -contains $n) { throw "refused: $n is needed for management or monitoring" }
      $svc = Get-Service -Name $n
      Stop-Service -InputObject $svc -Force
      $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
      $detail = "service $($svc.Name) ($($svc.DisplayName)) stopped"
    }
    'service-start' {
      $n = $pos[0]; if ($n -notmatch '^[\w.@$ -]{1,128}$') { throw 'invalid service name' }
      $svc = Get-Service -Name $n
      Start-Service -InputObject $svc
      $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
      $detail = "service $($svc.Name) started"
    }
    'block-port' {
      $proto = $pos[0].ToUpper(); $port = [int]$pos[1]
      if ($proto -notin @('TCP','UDP') -or $port -lt 1 -or $port -gt 65535) { throw 'invalid proto/port' }
      New-NetFirewallRule -Name "MamorAI-$ref-in" -DisplayName "MamorAI block $proto/$port ($ref)" -Group $Group -Direction Inbound -Action Block -Protocol $proto -LocalPort $port -Profile Any | Out-Null
      $detail = "inbound $proto/$port blocked"
    }
    'unblock-port' { $detail = "removed $(Remove-Ref $ref) rule(s) of $ref" }
    'block-ip' {
      $ip = Assert-Ip $pos[0]
      New-NetFirewallRule -Name "MamorAI-$ref-in" -DisplayName "MamorAI block $ip ($ref)" -Group $Group -Direction Inbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null
      New-NetFirewallRule -Name "MamorAI-$ref-out" -DisplayName "MamorAI block $ip ($ref)" -Group $Group -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any | Out-Null
      $detail = "traffic to/from $ip blocked"
    }
    'unblock-ip' { $detail = "removed $(Remove-Ref $ref) rule(s) of $ref" }
    'isolate' { $detail = Invoke-Isolate -AllowDns ([bool]$flags['allow-dns']) -AllowAd ([bool]$flags['allow-ad']) }
    'unisolate' { $detail = Invoke-Unisolate }
    default { throw "unknown operation: $op" }
  }
  $ex = @{ ref = $ref }; if ($op -eq 'version' -and $script:packRev) { $ex.pack = $script:packRev }
  foreach ($h in @($script:verExtra, $script:opExtra)) { if ($h) { foreach ($k in $h.Keys) { $ex[$k] = $h[$k] } } }
  Write-Result -Id $id -Op $op -Ok $true -Detail $detail -Extra $ex
  exit 0
} catch {
  Write-Result -Id $id -Op $op -Ok $false -Detail $_.Exception.Message -Extra @{}
  exit 1
}
