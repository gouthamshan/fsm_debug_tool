@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

rem --- Find a REAL python, not the Microsoft Store shim (WindowsApps\python.exe) ---
set "PY="
for /f "delims=" %%P in ('dir /s /b "%LOCALAPPDATA%\hermes\tools\python-*\python3.exe" 2^>nul') do set "PY=%%P"

if not defined PY (
  for /f "delims=" %%P in ('where python3 2^>nul') do (
    echo %%P | findstr /i "WindowsApps" >nul || set "PY=%%P"
  )
)
if not defined PY (
  for /f "delims=" %%P in ('where python 2^>nul') do (
    echo %%P | findstr /i "WindowsApps" >nul || set "PY=%%P"
  )
)

if defined PY (
  "%PY%" --version >nul 2>&1
  if errorlevel 1 set "PY="
)

if not defined PY (
  echo Python not found. Trying automatic install via winget...
  echo If prompted, approve the Python install. This is a one-time step.
  where winget >nul 2>&1
  if not errorlevel 1 (
    winget install -e --id Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements
    rem Refresh PATH in this window and search common install locations
    for /f "delims=" %%P in ('dir /s /b "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" 2^>nul') do set "PY=%%P"
    for /f "delims=" %%P in ('dir /s /b "C:\Program Files\Python312\python.exe" 2^>nul') do set "PY=%%P"
    for /f "delims=" %%P in ('where python 2^>nul') do (
      echo %%P | findstr /i "WindowsApps" >nul || set "PY=%%P"
    )
  )
)

if not defined PY (
  echo Python not found in Hermes tools or PATH, and winget install did not finish.
  echo Manual option: Install Python from https://www.python.org, tick "Add python.exe to PATH",
  echo then double-click this file again. Or run: winget install Python.Python.3.12
  echo The Store shim in WindowsApps is NOT a real Python - ignore that message.
  pause
  exit /b 1
)

echo Using Python: %PY%
"%PY%" --version
echo Starting FortiSIEM Log Terminal at http://127.0.0.1:8765
start "" http://127.0.0.1:8765
"%PY%" app.py --port 8765
pause
