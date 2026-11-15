<#
  MamorAI active-response add-on installer for Windows endpoints (EDR-121)
  Installs mamorai-ar.cmd / mamorai-ar.ps1 into the Wazuh agent's active-response\bin, after checking:
    - SHA-256 of every file against manifest.json
    - the signing certificate thumbprint against manifest.json
    - the Authenticode signature of mamorai-ar.ps1 (must be Valid and made by that certificate)
  Trusts the signing certificate on this machine (LocalMachine Root + TrustedPublisher) so that AllSigned can run it,
  makes sure active-responses.log is forwarded to Wazuh, and runs a local self-test (operation "version").
  Idempotent. Run as Administrator:
    powershell -NoProfile -ExecutionPolicy Bypass -File Install-MamoraiAddon.ps1 [-sourceDir <folder with the add-on>]
  Exit code 0 = installed and self-test OK. Also used by Install-EdrAgent.ps1 (-AddonOnly).
#>
param([string]$sourceDir = $PSScriptRoot, [switch]$NoRestart)
$ErrorActionPreference = 'Stop'
$sourceDir = $sourceDir.TrimEnd('\')
function Say([string]$m, [string]$lvl = 'INFO') { $c = @{ OK = 'Green'; WARN = 'Yellow'; ERROR = 'Red' }[$lvl]; if (-not $c) { $c = 'Cyan' }; Write-Host ("[mamorai-addon] {0} {1}" -f $lvl, $m) -ForegroundColor $c }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Say 'run as Administrator' 'ERROR'; exit 2 }
$agent = 'C:\Program Files (x86)\ossec-agent'
if (-not (Test-Path (Join-Path $agent 'wazuh-agent.exe'))) { Say "Wazuh agent not found in $agent" 'ERROR'; exit 3 }
$bin = Join-Path $agent 'active-response\bin'

# 1. manifest + hashes
$manPath = Join-Path $sourceDir 'manifest.json'
if (-not (Test-Path $manPath)) { Say "manifest.json not found in $sourceDir" 'ERROR'; exit 4 }
$man = Get-Content $manPath -Raw | ConvertFrom-Json
foreach ($p in $man.files.PSObject.Properties) {
  $f = Join-Path $sourceDir $p.Name
  if (-not (Test-Path $f)) { Say "missing file: $($p.Name)" 'ERROR'; exit 5 }
  $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower()
  if ($h -ne $p.Value.ToLower()) { Say "hash mismatch: $($p.Name) (the package was changed after it was built)" 'ERROR'; exit 6 }
}
Say "files match manifest (v$($man.version))" 'OK'

# 2. signing certificate
$cerPath = Join-Path $sourceDir 'mamorai-addon-signing.cer'
$cer = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)
if ($cer.Thumbprint -ne $man.signer_thumbprint.ToUpper()) { Say 'signing certificate does not match manifest' 'ERROR'; exit 7 }
foreach ($store in 'Root', 'TrustedPublisher') {
  if (-not (Get-ChildItem "Cert:\LocalMachine\$store" | Where-Object { $_.Thumbprint -eq $cer.Thumbprint })) {
    Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
    Say "trusted the add-on signing certificate in LocalMachine\$store ($($cer.Subject))" 'OK'
  }
}

# 3. signature of the script
$sig = Get-AuthenticodeSignature -LiteralPath (Join-Path $sourceDir 'mamorai-ar.ps1')
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $cer.Thumbprint) { Say "signature check failed: $($sig.Status) $($sig.StatusMessage)" 'ERROR'; exit 8 }
Say 'Authenticode signature is valid' 'OK'

# 4. install
foreach ($n in 'mamorai-ar.cmd', 'mamorai-ar.ps1') { Copy-Item -LiteralPath (Join-Path $sourceDir $n) -Destination (Join-Path $bin $n) -Force; Unblock-File -LiteralPath (Join-Path $bin $n) -ErrorAction SilentlyContinue }
Set-Content -LiteralPath (Join-Path $bin 'mamorai-ar.version') -Value $man.version -Encoding ASCII
Say "installed into $bin" 'OK'

# 5. active-responses.log must reach Wazuh (MamorAI reads the result from there)
$conf = Join-Path $agent 'ossec.conf'
$raw = Get-Content -LiteralPath $conf -Raw
$restart = $false
if ($raw -notmatch 'active-responses\.log') {
  Copy-Item -LiteralPath $conf "$conf.bak-mamorai-$(Get-Date -Format yyyyMMdd-HHmm)"
  $blk = "`r`n  <!-- MamorAI add-on: forward active-response results -->`r`n  <localfile>`r`n    <location>active-response\active-responses.log</location>`r`n    <log_format>syslog</log_format>`r`n  </localfile>`r`n"
  $i = $raw.LastIndexOf('</ossec_config>')
  $raw = $raw.Substring(0, $i) + $blk + $raw.Substring($i)
  [System.IO.File]::WriteAllText($conf, $raw, (New-Object System.Text.UTF8Encoding($false)))
  $restart = $true
  Say 'ossec.conf: added localfile for active-responses.log' 'OK'
} else { Say 'ossec.conf already forwards active-responses.log' 'OK' }
if ($restart -and -not $NoRestart) { Restart-Service WazuhSvc; Say 'WazuhSvc restarted' 'OK' }

# 6. self-test (proves AllSigned accepts the signature on this machine)
$log = Join-Path $agent 'active-response\active-responses.log'
$tag = 'minstall' + (Get-Random -Maximum 99999)
$req = '{"version":1,"command":"add","parameters":{"extra_args":["version","--id","' + $tag + '"]}}'
$req | & (Join-Path $bin 'mamorai-ar.cmd') | Out-Null
Start-Sleep -Milliseconds 500
$hit = Get-Content -LiteralPath $log -Tail 20 -ErrorAction SilentlyContinue | Where-Object { $_ -match $tag } | Select-Object -Last 1
if ($hit -and $hit -match '"ok":true') { Say "self-test OK: $($hit.Substring(0, [Math]::Min(160, $hit.Length)))" 'OK'; exit 0 }
Say "self-test failed (no result line). Check: powershell execution policy / signature. Last log lines: $((Get-Content -LiteralPath $log -Tail 3 -ErrorAction SilentlyContinue) -join ' | ')" 'ERROR'
exit 9
