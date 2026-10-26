# register_task.ps1
# mamorai_lcd.py をログオン時に自動起動する。
#   1) タスクスケジューラ登録を試す（ログオン時トリガーは環境により管理者権限が必要）
#   2) 権限エラーなら スタートアップフォルダにショートカットを作る（管理者不要）
# 使い方:
#   .\register_task.ps1 -RepoDir "C:\tools\turing-smart-screen-python" -PythonW "C:\tools\turing-smart-screen-python\.venv\Scripts\pythonw.exe"
#   -Mode Startup を付けると最初からスタートアップ方式にする
#   -Remove を付けると両方の登録を削除する
param(
    [Parameter(Mandatory = $true)]
    [string]$RepoDir,
    [string]$TaskName = "MamorAI_LCD",
    # 依存パッケージを入れた Python の pythonw.exe（未指定なら PATH から探す）
    [string]$PythonW = "",
    [ValidateSet("Auto", "Task", "Startup")]
    [string]$Mode = "Auto",
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

$script = Join-Path $RepoDir "mamorai_lcd.py"
$lnk    = Join-Path ([Environment]::GetFolderPath("Startup")) "$TaskName.lnk"

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $lnk) { Remove-Item $lnk }
    Write-Host "削除しました: タスク $TaskName / $lnk"
    return
}

if (-not (Test-Path $script)) { throw "mamorai_lcd.py が見つかりません: $script" }
if ($PythonW) { $pythonw = $PythonW } else { $pythonw = (Get-Command pythonw.exe).Source }
if (-not (Test-Path $pythonw)) { throw "pythonw が見つかりません: $pythonw" }
Write-Host "pythonw : $pythonw"
Write-Host "script  : $script"

function Register-AsTask {
    $action    = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$script`"" -WorkingDirectory $RepoDir
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    $trigger.Delay = "PT30S"   # USB/ネットワーク待ち
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                 -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
                 -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description "MamorAI attack map on Turing 3.5inch LCD" -Force | Out-Null
    Write-Host "登録完了(タスクスケジューラ): $TaskName"
    Write-Host "今すぐ起動: Start-ScheduledTask -TaskName $TaskName"
    Write-Host "停止     : Stop-ScheduledTask  -TaskName $TaskName"
}

function Register-AsStartup {
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    $sc.TargetPath       = $pythonw
    $sc.Arguments        = "`"$script`""
    $sc.WorkingDirectory = $RepoDir
    $sc.Description      = "MamorAI LCD"
    $sc.Save()
    Write-Host "登録完了(スタートアップ): $lnk"
    Write-Host "今すぐ起動: Start-Process `"$lnk`""
    Write-Host "停止     : Get-CimInstance Win32_Process -Filter `"Name='pythonw.exe'`" | ? CommandLine -like '*mamorai_lcd.py*' | % { Stop-Process -Id `$_.ProcessId }"
}

switch ($Mode) {
    "Task"    { Register-AsTask }
    "Startup" { Register-AsStartup }
    "Auto" {
        try {
            Register-AsTask
        } catch {
            Write-Warning "タスク登録失敗: $($_.Exception.Message)"
            Write-Warning "スタートアップフォルダ方式に切り替えます"
            Register-AsStartup
        }
    }
}
Write-Host "ログ     : $(Join-Path $RepoDir 'mamorai_lcd.log')"
