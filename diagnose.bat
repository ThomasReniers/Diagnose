@echo off
setlocal
set "SCRIPT=%~dp0diagnose.ps1"
if not exist "%SCRIPT%" set "SCRIPT=%~dp0..\Diagnose\diagnose.ps1"
if not exist "%SCRIPT%" (
  echo DIAGNOSE - ERROR: diagnose.ps1 not found beside this batch file or in ..\Diagnose. 1>&2
  exit /b 1
)
where pwsh.exe >nul 2>nul
if not errorlevel 1 (
  pwsh.exe -NoProfile -File "%SCRIPT%" %*
) else (
  powershell.exe -NoProfile -File "%SCRIPT%" %*
)
exit /b %ERRORLEVEL%
