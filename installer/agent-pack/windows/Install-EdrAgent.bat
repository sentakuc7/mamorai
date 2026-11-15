@echo off
rem MamorAI agent pack (Windows): double-click. Elevates to Administrator and asks install / update / add-on only.
set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%HERE%\Install-EdrAgent.ps1\" -sourceDir \"%HERE%\"'"
