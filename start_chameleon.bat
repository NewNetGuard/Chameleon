:<<'WINDOWS'
@echo off
rem ---------------------------------------------------------------------------
rem Chameleon launcher: double-click on Windows or Linux. Starts Chameleon,
rem installing or updating it from the unpacked package this file lives in,
rem and opens the web panel.
rem
rem This one file is both a Windows batch file and a Linux shell script.
rem Windows runs the part up to "exit /b"; Linux skips it as a heredoc.
rem On Windows, Chameleon runs as two Windows services; administrator rights
rem are asked for only to install, update or start them.
rem ---------------------------------------------------------------------------
rem Copyright (c) 2026 NewNetGuard
rem SPDX-License-Identifier: MPL-2.0
rem
rem This Source Code Form is subject to the terms of the Mozilla Public
rem License, v. 2.0. If a copy of the MPL was not distributed with this
rem file, You can obtain one at https://mozilla.org/MPL/2.0/.
setlocal EnableExtensions EnableDelayedExpansion
title Chameleon
cd /d "%~dp0"
set "TARGET=%ProgramFiles%\Chameleon"
set "PACKAGE="
set "VERSION="
if exist "%~dp0chameleon-svc.exe" if exist "%~dp0VERSION" (
  set "PACKAGE=%~dp0"
  for /f "usebackq delims=" %%v in ("%~dp0VERSION") do set "VERSION=%%v"
)
set "INSTALLED="
if exist "%TARGET%\VERSION" for /f "usebackq delims=" %%v in ("%TARGET%\VERSION") do set "INSTALLED=%%v"
if not defined PACKAGE if not defined INSTALLED (
  echo This folder is not an unpacked Chameleon for Windows package.
  echo Unpack chameleon-windows-^<version^>.zip and run start_chameleon.bat from that folder.
  pause
  exit /b 1
)

rem --- the part that needs administrator rights ---------------------------------
if "%~1"=="--elevated" (
  if defined PACKAGE if not "!VERSION!"=="!INSTALLED!" (
    echo Installing Chameleon !VERSION! ...
    rem The trailing dot keeps the closing quote from being escaped.
    "!PACKAGE!chameleon-svc.exe" install --source "!PACKAGE!."
    if errorlevel 1 (
      pause
      exit /b 1
    )
  )
  "%SystemRoot%\System32\sc.exe" start Chameleon >nul 2>&1
  "%SystemRoot%\System32\sc.exe" start ChameleonPanel >nul 2>&1
  exit /b 0
)

set "NEEDS_ADMIN="
if defined PACKAGE if not "!VERSION!"=="!INSTALLED!" set "NEEDS_ADMIN=1"
"%SystemRoot%\System32\sc.exe" query Chameleon | "%SystemRoot%\System32\find.exe" "RUNNING" >nul || set "NEEDS_ADMIN=1"
"%SystemRoot%\System32\sc.exe" query ChameleonPanel | "%SystemRoot%\System32\find.exe" "RUNNING" >nul || set "NEEDS_ADMIN=1"
if defined NEEDS_ADMIN (
  net session >nul 2>&1
  if errorlevel 1 (
    echo Chameleon needs administrator rights to set up its network protection.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '--elevated' -Verb RunAs -Wait -ErrorAction Stop } catch { exit 1 }"
    if errorlevel 1 (
      echo Administrator rights were not granted; Chameleon was not started.
      pause
      exit /b 1
    )
  ) else (
    call "%~f0" --elevated
  )
)

echo Starting the Chameleon panel ...
set "READY="
for /l %%i in (1,1,60) do (
  if not defined READY (
    netstat -an | "%SystemRoot%\System32\find.exe" "LISTENING" | "%SystemRoot%\System32\find.exe" ":8443 " >nul && set "READY=1"
    if not defined READY ping -n 2 127.0.0.1 >nul
  )
)
if not defined READY (
  echo The Chameleon panel did not start.
  pause
  exit /b 1
)
start "" "https://localhost:8443"
echo Chameleon Panel: https://localhost:8443
echo Chameleon is running.
echo Press any key to close this window.
pause >nul
exit /b 0
WINDOWS
# --- Linux ---------------------------------------------------------------------
# Runs as the desktop user (sudo asks for the password when needed). The panel
# password is created and reset in the panel itself, from this computer.

MODE="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SELF="$HERE/$(basename "$0")"
cd "$HERE" || exit 1

panel_url() {
  port="$(sed -n 's/^CHAMELEON_PANEL_PORT=//p' /etc/chameleon/panel.env 2>/dev/null)"
  port="${port:-8443}"
  if [ "$port" = "443" ]; then echo "https://localhost"; else echo "https://localhost:$port"; fi
}

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

# A double-click starts without a terminal: reopen in one, so sudo can ask
# for the password of this computer's account.
if [ "$MODE" != "--in-terminal" ] && [ ! -t 0 ]; then
  for terminal in x-terminal-emulator gnome-terminal konsole xfce4-terminal mate-terminal xterm; do
    if command -v "$terminal" >/dev/null 2>&1; then
      case "$terminal" in
        gnome-terminal) exec gnome-terminal -- sh "$SELF" --in-terminal ;;
        *) exec "$terminal" -e sh "$SELF" --in-terminal ;;
      esac
    fi
  done
  command -v notify-send >/dev/null 2>&1 \
    && notify-send "Chameleon" "Open a terminal and run: sh $SELF"
  exit 1
fi

# Waits for any single key (sh has no "read -n 1": switch the terminal to
# non-canonical mode for one byte). Every terminal start waits, not only the
# window this script opens itself: the file manager's "Run as a Program"
# (Nautilus 50 and later) also runs it in a terminal, which closes as soon as
# the script ends.
wait_key() {
  [ -t 0 ] || return 0
  printf 'Press any key to close this window. '
  saved="$(stty -g 2>/dev/null)"
  stty -icanon -echo 2>/dev/null
  dd bs=1 count=1 >/dev/null 2>&1
  [ -n "$saved" ] && stty "$saved" 2>/dev/null
  echo
}

fail() {
  echo "Chameleon: $*" >&2
  wait_key
  exit 1
}

if [ -n "$SUDO" ]; then
  command -v sudo >/dev/null 2>&1 || fail "sudo is required"
fi

# Install or update from the unpacked package this file lives in.
installed="$(cat /opt/chameleon/VERSION 2>/dev/null)"
if [ -f "$HERE/install.sh" ] && [ -f "$HERE/VERSION" ]; then
  version="$(tr -d '[:space:]' < "$HERE/VERSION")"
  if [ "$version" != "$installed" ]; then
    echo "Installing Chameleon $version ..."
    (cd "$HERE" && $SUDO ./install.sh) || fail "installation failed"
  fi
elif [ -z "$installed" ]; then
  fail "this folder is not an unpacked Chameleon package; unpack chameleon-panel-<version>.tar.gz and run start_chameleon.bat from there"
fi

$SUDO systemctl start chameleon-panel-firewall.service chameleon-guard.service \
  chameleon-dns.service chameleon-panel.service || fail "the Chameleon services did not start"

# Wait until the panel answers.
port="$(sed -n 's/^CHAMELEON_PANEL_PORT=//p' /etc/chameleon/panel.env 2>/dev/null)"
port="${port:-8443}"
tries=0
until ss -Htln "sport = :$port" 2>/dev/null | grep -q .; do
  tries=$((tries + 1))
  [ "$tries" -lt 40 ] || fail "the panel did not start; see: journalctl -u chameleon-panel"
  sleep 0.5
done

url="$(panel_url)"
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$url" >/dev/null 2>&1 &
fi
echo "Chameleon is running."
# The window stays until the user closes it: the installer's panel address,
# certificate fingerprint and one-time setup code must remain readable.
wait_key
exit 0
