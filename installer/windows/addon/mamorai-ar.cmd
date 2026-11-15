@echo off
rem MamorAI active-response add-on (EDR-121). Started by the Wazuh agent; the JSON request arrives on stdin.
rem The PowerShell body must carry a valid Authenticode signature (AllSigned), otherwise nothing runs.
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File "%~dp0mamorai-ar.ps1"
exit /b %ERRORLEVEL%
