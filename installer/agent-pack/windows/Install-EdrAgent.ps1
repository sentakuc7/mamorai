<#
  MamorAI agent pack - Windows endpoint installer (EDR-130)

  Installs or updates, on one PC:
    [Tailscale (laptops, when the pack has a Tailscale address)] -> Wazuh agent -> Sysmon -> MamorAI add-on
  and checks that the agent reaches the Wazuh manager. Settings come from config.json next to this script,
  which MamorAI generates (host screen -> "Agent pack"). Safe to run again.

  Mode (asked on screen when not given):
    install  new PC: install everything and enroll the agent
    update   PC that already has the agent: apply this pack's settings, Sysmon config and add-on,
             and upgrade the agent if it is older than the pack (enrollment is kept)
    addon    only the MamorAI add-on (signed active-response script for host actions)

  Usage:
    Install-EdrAgent.bat                                   double-click (asks)
    Install-EdrAgent.ps1 -Mode update -Unattended          GPO / Intune / PDQ / scheduled task (no questions, exit code)
    Install-EdrAgent.ps1 -Mode install -DeviceType desktop -RegistrationPassword <pw> -Unattended
    Install-EdrAgent.ps1 -AddonOnly                        same as -Mode addon (older scripts)

  After a successful run the extracted pack (it holds the Tailscale key / enrollment password) and its zip in
  Downloads are deleted automatically. Not on a network share, and not with -KeepFiles.

  Exit code: 0 = done, 1 = failed, 2 = cancelled.   Log: %ProgramData%\MamorAI\agent-install.log
#>
param(
  [string]$sourceDir = $PSScriptRoot,
  [ValidateSet('auto','install','update','addon')][string]$Mode = 'auto',
  [ValidateSet('auto','laptop','desktop')][string]$DeviceType = 'auto',
  [switch]$AddonOnly,
  [string]$RegistrationPassword = '',
  [string]$TailscaleAuthKey = '',
  [switch]$Unattended,
  [switch]$KeepFiles
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 and older: the progress bar makes Invoke-WebRequest / file copies very slow
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$sourceDir = $sourceDir.TrimEnd('\')
if ($AddonOnly) { $Mode = 'addon' }
$StateDir = Join-Path $env:ProgramData 'MamorAI'
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$LogFile = Join-Path $StateDir 'agent-install.log'
$StateFile = Join-Path $StateDir 'pack.json'
$AgentDir = 'C:\Program Files (x86)\ossec-agent'
$OssecConf = Join-Path $AgentDir 'ossec.conf'
$script:rc = 0
# set only when the last step is reached; anything else that leaves the try block is a failure (EDR-170)
$script:done = $false
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor 12288 }
catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

function Log {
  param([string]$Msg, [string]$Level = 'INFO')
  $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg
  $color = switch ($Level) { 'OK' {'Green'} 'WARN' {'Yellow'} 'ERROR' {'Red'} 'STEP' {'Magenta'} default {'Cyan'} }
  Write-Host $line -ForegroundColor $color
  try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 } catch { }
}
function Fail { param([string]$Msg) Log $Msg 'ERROR'; $script:rc = 1; throw "EDR_FAIL: $Msg" }
function Run-Native {
  # Run a native exe without tripping ErrorActionPreference=Stop on stderr output. Returns the exit code.
  param([string]$Exe, [string]$Arguments, [int]$Tail = 2, [switch]$Secret)
  $o = Join-Path $env:TEMP 'edr-native-out.txt'; $e = Join-Path $env:TEMP 'edr-native-err.txt'
  $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e
  if (-not $Secret) { @(Get-Content $o, $e -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne '' }) | Select-Object -Last $Tail | ForEach-Object { Log "  $_" } }
  Remove-Item $o, $e -Force -ErrorAction SilentlyContinue
  return $p.ExitCode
}
function Test-Tcp {
  param([string]$TargetHost, [int]$Port, [int]$TimeoutMs = 3000)
  $c = New-Object System.Net.Sockets.TcpClient
  try { $ar = $c.BeginConnect($TargetHost, $Port, $null, $null); if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }; $c.EndConnect($ar); return $true }
  catch { return $false } finally { $c.Close() }
}
function Get-Payload {
  # A file bundled in the pack (offline pack) is used first; otherwise it is downloaded.
  param([string]$LocalName, [string]$Url, [string]$Dest)
  $local = Join-Path $sourceDir $LocalName
  if (Test-Path -LiteralPath $local) { Copy-Item -LiteralPath $local -Destination $Dest -Force; Log "  using bundled $LocalName" 'OK'; return }
  Log "  downloading $Url"
  try { Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing }
  catch { Fail ("Download failed ({0}). Use the offline pack (MamorAI -> Agent pack -> offline) or put '{1}' next to this script. Reason: {2}" -f $Url, $LocalName, $_.Exception.Message) }
}
function Assert-Signed {
  # Installers and Sysmon are only run when they carry a valid signature of the expected publisher.
  param([string]$File, [string]$Publisher)
  $s = Get-AuthenticodeSignature -LiteralPath $File
  if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch $Publisher) { Fail "signature check failed for $(Split-Path $File -Leaf): $($s.Status) $($s.SignerCertificate.Subject)" }
  Log "  signature OK: $(Split-Path $File -Leaf) ($Publisher)" 'OK'
}
function Expand-Zip {
  # Expand-Archive needs PowerShell 5.0 (Windows Server 2012 R2 ships 4.0): use .NET 4.5 instead, overwriting existing files
  param([string]$Zip, [string]$Dest)
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  $root = [System.IO.Path]::GetFullPath($Dest).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
  $z = [System.IO.Compression.ZipFile]::OpenRead($Zip)
  try {
    foreach ($en in $z.Entries) {
      $target = [System.IO.Path]::GetFullPath((Join-Path $Dest $en.FullName))
      if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { Fail "unsafe path in $(Split-Path $Zip -Leaf): $($en.FullName)" }
      if ($en.FullName.EndsWith('/') -or $en.FullName.EndsWith('\')) { New-Item -ItemType Directory -Force -Path $target | Out-Null; continue }
      New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent) | Out-Null
      [System.IO.Compression.ZipFileExtensions]::ExtractToFile($en, $target, $true)
    }
  } finally { $z.Dispose() }
  Log "  extracted $(Split-Path $Zip -Leaf) -> $Dest" 'OK'
}
function Ask {
  param([string]$Prompt, [string[]]$Allowed)
  do { $a = (Read-Host $Prompt).Trim().ToUpper() } while ($Allowed -notcontains $a)
  return $a
}

# ---- 0. administrator --------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  if ($RegistrationPassword -or $TailscaleAuthKey -or $Unattended) { Write-Host 'Run this as Administrator (or as SYSTEM from GPO / Intune).' -ForegroundColor Red; exit 1 }
  Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -sourceDir `"$sourceDir`" -Mode $Mode -DeviceType $DeviceType"
  exit 0
}

try {
Log "===== MamorAI agent pack: start (host $env:COMPUTERNAME, mode $Mode) =====" 'STEP'
Log "PowerShell $($PSVersionTable.PSVersion) / $([Environment]::OSVersion.VersionString)"
if ($PSVersionTable.PSVersion.Major -lt 3) { Fail 'PowerShell 3.0 or later is required (install WMF 5.1)' }

# ---- 1. pack and config -------------------------------------------------------
$cfgPath = Join-Path $sourceDir 'config.json'
if (-not (Test-Path -LiteralPath $cfgPath)) { Fail "config.json not found in $sourceDir" }
$cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
$pack = $null; $pp = Join-Path $sourceDir 'pack.json'
if (Test-Path -LiteralPath $pp) { $pack = Get-Content -LiteralPath $pp -Raw | ConvertFrom-Json }
$packRev = if ($pack) { [int]$pack.rev } else { 0 }
foreach ($k in 'wazuhVersion') { if (-not $cfg.$k) { Fail "config.json: '$k' is empty" } }
if (-not $cfg.managerLanIp -and -not $cfg.managerTailnetIp -and -not $cfg.managerPublicAddress) { Fail 'config.json: no manager address' }

# files from a downloaded zip carry the 'from the internet' mark; drop it so the signed add-on runs under AllSigned
Get-ChildItem -LiteralPath $sourceDir -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
# integrity of the pack (SHA256SUMS.txt written by MamorAI)
$sums = Join-Path $sourceDir 'SHA256SUMS.txt'
if (Test-Path -LiteralPath $sums) {
  $bad = @()
  foreach ($l in Get-Content -LiteralPath $sums) {
    if ($l -notmatch '^([0-9a-f]{64})\s+(.+)$') { continue }
    $f = Join-Path $sourceDir ($Matches[2] -replace '/', '\')
    if (-not (Test-Path -LiteralPath $f)) { $bad += "$($Matches[2]) (missing)"; continue }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower() -ne $Matches[1]) { $bad += $Matches[2] }
  }
  if ($bad.Count) { Fail "pack files were changed after MamorAI built them: $($bad -join ', ')" }
  Log "pack r${packRev}: all files match SHA256SUMS.txt" 'OK'
} else { Log 'SHA256SUMS.txt not found: integrity of the pack is not checked' 'WARN' }

# ---- 2. what is on this PC ----------------------------------------------------
$svc = Get-Service WazuhSvc -ErrorAction SilentlyContinue
$agentVer = $null
$un = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Wazuh Agent*' } | Select-Object -First 1
if ($un -and $un.DisplayVersion) { $agentVer = [string]$un.DisplayVersion }
elseif (Test-Path (Join-Path $AgentDir 'wazuh-agent.exe')) { $agentVer = (Get-Item (Join-Path $AgentDir 'wazuh-agent.exe')).VersionInfo.ProductVersion }
$state = $null; if (Test-Path -LiteralPath $StateFile) { try { $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json } catch { $state = $null } }
$addonFile = Join-Path $AgentDir 'active-response\bin\mamorai-ar.version'
$addonVer = if (Test-Path -LiteralPath $addonFile) { (Get-Content -LiteralPath $addonFile -Raw).Trim() } else { $null }
$packAddon = if ($pack -and $pack.addon_version) { $pack.addon_version } else { '-' }
Write-Host ''
Write-Host ("  This pack : r{0}  (Wazuh agent {1}, add-on {2})" -f $packRev, $cfg.wazuhVersion, $packAddon) -ForegroundColor White
Write-Host ("  This PC   : agent {0} / pack {1} / add-on {2}" -f $(if ($svc) { $agentVer } else { 'not installed' }), $(if ($state) { "r$($state.rev)" } else { '-' }), $(if ($addonVer) { $addonVer } else { '-' })) -ForegroundColor White
Write-Host ''

# ---- 3. mode -----------------------------------------------------------------
if ($Mode -eq 'auto') {
  if (-not $svc) {
    if ($Unattended) { $Mode = 'install' }
    else { if ((Ask '  The Wazuh agent is not installed. Install now? [Y/N]' @('Y','N')) -eq 'N') { $script:rc = 2; throw 'EDR_CANCEL' }; $Mode = 'install' }
  } elseif ($Unattended) { $Mode = 'update' }
  else {
    Write-Host '  The Wazuh agent is already installed. What do you want to do?' -ForegroundColor White
    Write-Host '    [1] Update (recommended) - settings, Sysmon and add-on from this pack; upgrade the agent if it is older' -ForegroundColor Yellow
    Write-Host '    [2] Add-on only          - install / update only the MamorAI add-on' -ForegroundColor Yellow
    Write-Host '    [Q] Quit' -ForegroundColor Yellow
    switch (Ask '  Enter 1, 2 or Q' @('1','2','Q')) { '1' { $Mode = 'update' } '2' { $Mode = 'addon' } 'Q' { $script:rc = 2; throw 'EDR_CANCEL' } }
  }
}
if ($Mode -in @('update','addon') -and -not $svc) { Fail "the Wazuh agent is not installed on this PC: use -Mode install" }
if ($Mode -eq 'install' -and $svc) { Log 'the Wazuh agent is already installed: continuing as an update (enrollment is kept)' 'WARN'; $Mode = 'update' }
Log "mode: $Mode" 'STEP'

# ---- MamorAI add-on ------------------------------------------------------------
function Install-Addon {
  param([switch]$NoRestart)
  $addonDir = Join-Path $sourceDir 'addon'
  $inst = Join-Path $addonDir 'Install-MamoraiAddon.ps1'
  if (-not (Test-Path -LiteralPath $inst)) { Log 'MamorAI add-on is not in this pack -> skipped (host actions from MamorAI will not work on this PC)' 'WARN'; return }
  Log 'MamorAI add-on (hash + signature check)...'
  $a = "-NoProfile -ExecutionPolicy Bypass -File `"$inst`" -sourceDir `"$addonDir`"" + $(if ($NoRestart) { ' -NoRestart' } else { '' })
  $r = Run-Native 'powershell.exe' $a 8
  if ($r -eq 0) { Log 'MamorAI add-on installed, self-test OK' 'OK' } else { Log "MamorAI add-on failed (exit $r). The agent itself is not affected." 'WARN'; if ($script:rc -eq 0) { $script:rc = 1 } }
}
function Save-State {
  param([string]$Type)
  $o = [ordered]@{ rev = $packRev; os = 'windows'; mode = $Mode; deviceType = $Type; wazuh = $cfg.wazuhVersion; addon = $packAddon; installed_at = (Get-Date).ToString('o') }
  [System.IO.File]::WriteAllText($StateFile, ($o | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
}

if ($Mode -eq 'addon') {
  Install-Addon
  Save-State $(if ($state) { $state.deviceType } else { '' })
  Log "===== add-on only: done (pack r$packRev) =====" 'OK'
  $script:done = $true
  return
}

$tmp = Join-Path $env:TEMP 'mamorai-agent-pack'; New-Item -ItemType Directory -Force -Path $tmp | Out-Null

# ---- 4. device type ---------------------------------------------------------------
$canLaptop = [bool]($cfg.managerTailnetIp -or $cfg.managerPublicAddress)
if ($DeviceType -eq 'auto' -and $cfg.deviceType -in @('laptop','desktop')) { $DeviceType = $cfg.deviceType }
if ($DeviceType -eq 'auto' -and $Mode -eq 'update' -and $state -and $state.deviceType -in @('laptop','desktop')) { $DeviceType = $state.deviceType }
if ($DeviceType -eq 'auto' -and $Mode -eq 'update' -and (Test-Path $OssecConf)) {
  $raw0 = Get-Content $OssecConf -Raw
  $DeviceType = if ($cfg.managerTailnetIp -and $raw0 -match [regex]::Escape("<address>$($cfg.managerTailnetIp)</address>")) { 'laptop' } else { 'desktop' }
  Log "device type taken from the current settings: $DeviceType"
}
if ($DeviceType -eq 'auto') {
  if (-not $canLaptop) { $DeviceType = 'desktop' }
  elseif ($Unattended) { $DeviceType = 'desktop'; Log 'unattended without -DeviceType: using desktop (LAN)' 'WARN' }
  else {
    Write-Host ''
    Write-Host '  Select the device type' -ForegroundColor White
    Write-Host '    [1] Laptop  - taken outside; connects from anywhere' -ForegroundColor Yellow
    Write-Host '    [2] Desktop - stays on the office / home LAN' -ForegroundColor Yellow
    $DeviceType = if ((Ask '  Enter 1 or 2' @('1','2')) -eq '1') { 'laptop' } else { 'desktop' }
  }
}
if ($DeviceType -eq 'laptop' -and -not $canLaptop) { Log 'this pack has no Tailscale / public address for the manager: using desktop (LAN)' 'WARN'; $DeviceType = 'desktop' }
$useTailscale = ($DeviceType -eq 'laptop' -and [bool]$cfg.managerTailnetIp)
if ($DeviceType -eq 'laptop') { $want = @($cfg.managerTailnetIp, $cfg.managerPublicAddress, $cfg.managerLanIp) | Where-Object { $_ } ; $group = $cfg.groupLaptop }
else { $want = @($cfg.managerLanIp, $cfg.managerPublicAddress) | Where-Object { $_ }; $group = $cfg.groupDesktop }
$want = @($want | Select-Object -Unique)
if (-not $want.Count) { Fail "no manager address for a $DeviceType in this pack" }
if (-not $group) { $group = 'default' }
$mgr = $want[0]
Log "device type $DeviceType | manager $($want -join ' -> ') | group $group | Wazuh agent $($cfg.wazuhVersion)"

# ---- 5. Tailscale (laptops) -----------------------------------------------------------
if ($useTailscale) {
  Log '--- Tailscale ---' 'STEP'
  $tsExe = 'C:\Program Files\Tailscale\tailscale.exe'
  if (-not (Test-Path $tsExe)) {
    $tsMsi = Join-Path $tmp 'tailscale.msi'
    Get-Payload -LocalName 'tailscale-setup.msi' -Url 'https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi' -Dest $tsMsi
    Assert-Signed $tsMsi 'Tailscale'
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$tsMsi`" /quiet /norestart"
    if ($p.ExitCode -ne 0) { Fail "Tailscale MSI exit code $($p.ExitCode)" }
    Start-Sleep 5
    if (-not (Test-Path $tsExe)) { Fail 'tailscale.exe not found after install' }
    Log 'Tailscale installed' 'OK'
  } else { Log 'Tailscale already installed' 'OK' }
  $tsStatus = (& $tsExe status 2>&1 | Out-String)
  if ($tsStatus -match 'Logged out|NeedsLogin|Stopped') {
    $tsKey = if ($TailscaleAuthKey) { $TailscaleAuthKey } else { [string]$cfg.tailscaleAuthKey }
    if ($tsKey) {
      Log 'joining the tailnet with the auth key...'
      if ((Run-Native $tsExe "up --authkey=$tsKey --unattended" 3 -Secret) -ne 0) { Fail 'tailscale up failed (is the auth key still valid?)' }
    } elseif ($Unattended) { Fail 'Tailscale is not logged in and no auth key was given (-TailscaleAuthKey)' }
    else {
      Log 'no auth key -> a browser window opens; sign in with the tailnet account and approve' 'WARN'
      Start-Process -FilePath $tsExe -ArgumentList 'up --unattended' -WindowStyle Hidden
      $deadline = (Get-Date).AddMinutes(5); $opened = ''
      do {
        Start-Sleep 5
        $tsStatus = (& $tsExe status 2>&1 | Out-String)
        if ($tsStatus -match 'Log in at: (https://\S+)' -and $Matches[1] -ne $opened) { $opened = $Matches[1]; Write-Host "  >>> approve in the browser: $opened" -ForegroundColor Yellow; Start-Process $opened }
      } while (($tsStatus -match 'Logged out|NeedsLogin') -and (Get-Date) -lt $deadline)
      if ($tsStatus -match 'Logged out|NeedsLogin') { Fail 'Tailscale sign-in was not completed within 5 minutes' }
    }
  }
  Log "tailnet IP of this PC: $(& $tsExe ip -4 2>$null | Select-Object -First 1)" 'OK'
}

# ---- 6. manager reachable --------------------------------------------------------------
$reach = $null
foreach ($m in $want) { for ($i = 1; $i -le 3 -and -not $reach; $i++) { if (Test-Tcp $m 1514 3000) { $reach = $m } else { Start-Sleep 2 } } ; if ($reach) { break } }
if (-not $reach) {
  if ($Mode -eq 'install') { Fail "cannot reach the manager ($($want -join ', ')) on 1514/tcp. Check the network / firewall, or choose the other device type." }
  Log "cannot reach the manager right now ($($want -join ', ')). The settings are applied anyway; the agent connects when the network allows." 'WARN'
} else { Log "manager reachable: ${reach}:1514" 'OK'; $mgr = $reach }

# ---- 7. Wazuh agent -----------------------------------------------------------------------
Log '--- Wazuh agent ---' 'STEP'
$packVer = [version](($cfg.wazuhVersion -replace '-\d+$', ''))
$haveVer = $null; if ($agentVer -and $agentVer -match '(\d+\.\d+\.\d+)') { $haveVer = [version]$Matches[1] }
$needMsi = ($Mode -eq 'install') -or ($haveVer -and $haveVer -lt $packVer)
if ($Mode -eq 'update' -and $haveVer -and $haveVer -gt $packVer) { Log "agent $haveVer is newer than this pack ($packVer): kept" 'WARN' }
if ($needMsi) {
  $msi = Join-Path $tmp "wazuh-agent-$($cfg.wazuhVersion).msi"
  Get-Payload -LocalName "wazuh-agent-$($cfg.wazuhVersion).msi" -Url "https://packages.wazuh.com/4.x/windows/wazuh-agent-$($cfg.wazuhVersion).msi" -Dest $msi
  Assert-Signed $msi 'Wazuh'
  if ($Mode -eq 'install') {
    $pw = if ($RegistrationPassword) { $RegistrationPassword } else { [string]$cfg.registrationPassword }
    if (-not $pw) {
      if ($Unattended) { Fail 'enrollment password missing: pass -RegistrationPassword or download the pack with the password' }
      $sec = Read-Host '  Wazuh enrollment password (ask your administrator)' -AsSecureString
      $pw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
      if (-not $pw) { Fail 'enrollment password is required' }
    }
    Log "installing the Wazuh agent $($cfg.wazuhVersion) (enrolling via $mgr, group $group)..."
    $r = Run-Native msiexec.exe "/i `"$msi`" /q WAZUH_MANAGER=$mgr WAZUH_REGISTRATION_SERVER=$mgr WAZUH_REGISTRATION_PASSWORD=$pw WAZUH_AGENT_GROUP=$group" 0 -Secret
    $pw = $null
    if ($r -ne 0) { Fail "Wazuh agent MSI exit code $r" }
    Log 'Wazuh agent installed' 'OK'
  } else {
    Log "upgrading the Wazuh agent $haveVer -> $packVer (enrollment is kept)..."
    $r = Run-Native msiexec.exe "/i `"$msi`" /q" 0
    if ($r -ne 0 -and $r -ne 3010) { Fail "Wazuh agent upgrade: MSI exit code $r" }
    Log 'Wazuh agent upgraded' 'OK'
  }
} else { Log "Wazuh agent ${agentVer}: no change needed" 'OK' }

# <server> list in ossec.conf (manager order for this device type)
[xml]$xml = Get-Content $OssecConf -Raw
$client = $xml.ossec_config.client
$have = @($client.SelectNodes('server') | ForEach-Object { $_.address })
if (($have -join ',') -ne ($want -join ',')) {
  Copy-Item $OssecConf "$OssecConf.bak-$(Get-Date -Format yyyyMMdd-HHmm)"
  $client.SelectNodes('server') | ForEach-Object { [void]$client.RemoveChild($_) }
  $anchor = $client.FirstChild
  foreach ($ip in $want) {
    $s = $xml.CreateElement('server')
    foreach ($kv in @(@('address',$ip), @('port','1514'), @('protocol','tcp'))) { $e = $xml.CreateElement($kv[0]); $e.InnerText = $kv[1]; [void]$s.AppendChild($e) }
    if ($anchor) { [void]$client.InsertBefore($s, $anchor) } else { [void]$client.AppendChild($s) }
  }
  $xml.Save($OssecConf)
  Log "ossec.conf <server>: $($want -join ' -> ')" 'OK'
} else { Log 'ossec.conf <server>: already correct' 'OK' }

# ---- 8. Sysmon ------------------------------------------------------------------------------------
if ($cfg.sysmon -ne $false) {
  Log '--- Sysmon ---' 'STEP'
  $sysDir = 'C:\Sysmon'; New-Item -ItemType Directory -Force -Path $sysDir | Out-Null
  $sysExe = Join-Path $sysDir 'Sysmon64.exe'; $sysCfg = Join-Path $sysDir 'sysmonconfig.xml'
  Get-Payload -LocalName 'sysmonconfig.xml' -Url $cfg.sysmonConfigUrl -Dest $sysCfg
  try { [xml](Get-Content -LiteralPath $sysCfg -Raw) | Out-Null } catch { Fail 'the Sysmon config is not valid XML' }
  if (-not (Test-Path $sysExe)) {
    $zip = Join-Path $tmp 'Sysmon.zip'
    Get-Payload -LocalName 'Sysmon.zip' -Url 'https://download.sysinternals.com/files/Sysmon.zip' -Dest $zip
    Expand-Zip $zip $sysDir
  }
  Assert-Signed $sysExe 'Microsoft'
  if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    $r = Run-Native $sysExe "-accepteula -c `"$sysCfg`"" 1
    if ($r -ne 0) { Log "Sysmon config update returned $r" 'WARN' } else { Log 'Sysmon config updated' 'OK' }
  } else {
    $r = Run-Native $sysExe "-accepteula -i `"$sysCfg`"" 2
    if ($r -ne 0) { Fail "Sysmon install returned $r" }
    Log 'Sysmon installed' 'OK'
  }
} else { Log '--- Sysmon: not part of this pack ---' 'STEP' }

# ---- 9. MamorAI add-on ----------------------------------------------------------------------------
Log '--- MamorAI add-on ---' 'STEP'
Install-Addon -NoRestart

# ---- 10. start and verify --------------------------------------------------------------------------
Save-State $DeviceType
$started = Get-Date
Restart-Service WazuhSvc
Log 'WazuhSvc restarted, waiting for the manager connection...'
$logPath = Join-Path $AgentDir 'ossec.log'
$connected = $false; $deadline = (Get-Date).AddSeconds(120); $err = ''
do {
  Start-Sleep 5
  $tail = Get-Content $logPath -Tail 60 -ErrorAction SilentlyContinue | Where-Object { $_ -match '^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)' -and [datetime]::ParseExact($Matches[1], 'yyyy/MM/dd HH:mm:ss', $null) -ge $started.AddSeconds(-5) }
  if ($tail | Where-Object { $_ -match 'Connected to the server' }) { $connected = $true }
  $e1 = $tail | Where-Object { $_ -match 'Invalid password|Unable to connect to enrollment|ERROR' } | Select-Object -Last 1; if ($e1) { $err = $e1 }
} while (-not $connected -and (Get-Date) -lt $deadline)
if ($connected) { Log 'agent connected to the manager' 'OK' }
else { Log "no 'Connected to the server' within 120 s. Last error: $err" 'WARN'; Log "check: Get-Content '$logPath' -Tail 20" 'WARN'; if ($Mode -eq 'install') { $script:rc = 1 } }

Log "===== done: mode $Mode | pack r$packRev | type $DeviceType | group $group | log $LogFile =====" $(if ($script:rc -eq 0) { 'OK' } else { 'WARN' })
$script:done = $true
}
catch {
  if ($_.Exception.Message -eq 'EDR_CANCEL') { Log 'cancelled' 'WARN' }
  elseif ($_.Exception.Message -notlike 'EDR_FAIL:*') {
    Log ('UNEXPECTED ERROR: ' + $_.Exception.Message) 'ERROR'
    Log ('  at: ' + $_.InvocationInfo.PositionMessage.Trim()) 'ERROR'
    $script:rc = 1
  }
  if ($script:rc -eq 0) { $script:rc = 1 }
}
finally {
  if (-not $script:done -and $script:rc -eq 0) {
    # Ctrl+C or a stop that PowerShell did not report as an error: never treat it as success (EDR-170)
    Log 'INTERRUPTED: the installer stopped before the last step. Nothing was cleaned up; run it again.' 'ERROR'
    $script:rc = 1
  }
  if ($script:rc -eq 1) { Write-Host "`n*** FAILED. See $LogFile ***" -ForegroundColor Red }
  elseif ($script:rc -eq 0) { Write-Host "`nAll done. MamorAI shows this PC on the host screen after the next import (or press 'Import from Wazuh')." -ForegroundColor Green }
  # EDR-138: delete the extracted pack (it holds secrets) after success, unless it is shared or -KeepFiles
  $cleanDir = $null; $zips = @()
  try {
    $onShare = $sourceDir.StartsWith('\\')
    if (-not $onShare) { $drv = Get-PSDrive -Name ($sourceDir.Substring(0, 1)) -ErrorAction SilentlyContinue; if ($drv -and $drv.DisplayRoot -like '\\*') { $onShare = $true } }
    $leaf = Split-Path $sourceDir -Leaf
    if ($script:rc -eq 0 -and -not $KeepFiles -and -not $onShare -and $leaf -match '^MamorAI-Agent-Windows-r\d+' -and (Test-Path -LiteralPath (Join-Path $sourceDir 'pack.json'))) {
      $c = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
      $c.registrationPassword = ''; $c.tailscaleAuthKey = ''
      [System.IO.File]::WriteAllText($cfgPath, ($c | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
      $cleanDir = $sourceDir
      $parent = Split-Path $sourceDir -Parent
      if ($parent -and (Split-Path $parent -Leaf) -match '^MamorAI-Agent-Windows-r\d+' -and @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 1) { $cleanDir = $parent }  # "Extract all" makes a folder inside a folder
      $top = "MamorAI-Agent-Windows-r$packRev"
      foreach ($d in @((Split-Path $cleanDir -Parent), (Join-Path $env:USERPROFILE 'Downloads')) | Select-Object -Unique) {
        if ($d -and (Test-Path -LiteralPath $d)) { $zips += @(Get-ChildItem -LiteralPath $d -Filter "$top*.zip" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^$top(-offline)?( \(\d+\))?\.zip$" }) }
      }
      foreach ($z in $zips) { Remove-Item -LiteralPath $z.FullName -Force -ErrorAction SilentlyContinue; Log "deleted the pack zip: $($z.FullName)" 'OK' }
      Log "the extracted pack will be deleted: $cleanDir (use -KeepFiles to keep it)" 'OK'
    } elseif ($script:rc -eq 0 -and $onShare) { Log 'the pack is on a network share: not deleted (restrict who can read the share, and remove it when you are done)' 'WARN' }
  } catch { Log "could not clean up the pack: $($_.Exception.Message)" 'WARN' }
  if (-not $Unattended -and [Environment]::UserInteractive) { Read-Host 'Press Enter to close' | Out-Null }
  if ($cleanDir) {
    Set-Location $env:TEMP
    # the folder holds this running script: remove it from a separate process a moment later
    Start-Process cmd.exe -ArgumentList "/c timeout /t 3 /nobreak >nul & rmdir /s /q `"$cleanDir`"" -WindowStyle Hidden
  }
}
exit $script:rc
