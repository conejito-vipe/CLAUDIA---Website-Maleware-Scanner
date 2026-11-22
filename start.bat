@echo off
setlocal EnableExtensions
title CLAUDIA
cd /d "%~dp0"

rem  EINZIGE Startdatei. Sie richtet alles selbst ein (Python, Bausteine, Startbildschirm) und startet CLAUDIA.
rem  Es muss nichts von Hand installiert werden. Protokoll: %APPDATA%\CLAUDIA\start.log
rem  Hinweis: Eine .bat-Datei kann kein eigenes Symbol tragen. Beim ersten Start legt sie deshalb
rem  die Verknuepfung CLAUDIA.lnk mit dem Eichhoernchen-Symbol an; ab dann bitte diese benutzen.

set "LOGDIR=%APPDATA%\CLAUDIA"
set "LOG=%LOGDIR%\start.log"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" >nul 2>&1

if not exist "claudia\launcher.py" (
    echo.
    echo  CLAUDIA wurde nicht aus einem entpackten Ordner gestartet.
    echo  Bitte die ZIP-Datei zuerst entpacken ^(Rechtsklick, "Alle extrahieren"^)
    echo  und dann start.bat im entpackten Ordner doppelklicken.
    echo.
    pause
    exit /b 1
)

set "PY="
call :find_python
if not defined PY (
    call :install_python
    call :find_python
)
if not defined PY goto :python_failed

rem --- Verknuepfung mit Eichhoernchen-Symbol (nur einmal, im Programmordner)
if not exist "CLAUDIA.lnk" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "claudia\make_shortcut.ps1" -Folder "%~dp0." >nul 2>&1
)

rem --- Beim allerersten Start: Startbildschirm (PySide6) einmalig einrichten, damit alle Fenster gleich aussehen
if not exist ".venv\qt.ok" (
    echo.
    echo  CLAUDIA richtet beim ersten Start einmalig den Startbildschirm ein
    echo  ^(Download von pypi.org, ca. 80 MB^). Bitte warten. Dieses Fenster
    echo  schliesst sich danach von selbst.
    echo.
    %PY% -m claudia.launcher --bootstrap
)

rem --- Startbildschirm ohne Konsole starten (pythonw = Python ohne Konsolenfenster, liegt neben python.exe)
set "PYW="
%PY% -c "import sys,os;print(os.path.join(os.path.dirname(sys.executable),'pythonw.exe'))" > "%TEMP%\claudia_pyw.txt" 2>nul
if exist "%TEMP%\claudia_pyw.txt" set /p PYW=<"%TEMP%\claudia_pyw.txt"
del "%TEMP%\claudia_pyw.txt" >nul 2>&1
if defined PYW if exist "%PYW%" (
    start "" "%PYW%" -m claudia.launcher
    exit /b 0
)
where pyw >nul 2>&1
if not errorlevel 1 (
    start "" pyw -3 -m claudia.launcher
    exit /b 0
)
where pythonw >nul 2>&1
if not errorlevel 1 (
    start "" pythonw -m claudia.launcher
    exit /b 0
)
rem --- Notfall: ohne pyw/pythonw laeuft der Startbildschirm mit sichtbarem schwarzem Fenster
%PY% -m claudia.launcher
if errorlevel 1 (
    echo.
    echo  Das Programm wurde mit einem Fehler beendet. Protokoll: %%APPDATA%%\CLAUDIA\launcher.log
    pause
)
exit /b 0


rem ------------------------------------------------------------------ Unterprogramme
:find_python
rem  Sucht Python 3.9 oder neuer: erst py-Starter und PATH, dann die Standardordner der Benutzer-Installation
rem  (so wird auch eine eben erst installierte Version ohne Neustart gefunden).
set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,9) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY exit /b 0
python -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,9) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY exit /b 0
for %%V in (313 312 311 310 39) do (
    if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe" set PY="%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe"
)
exit /b 0

:install_python
echo.
echo  CLAUDIA
echo  -----------------------
echo  Python 3.9 oder neuer wurde nicht gefunden.
echo  CLAUDIA laedt Python jetzt automatisch von python.org herunter und
echo  installiert es nur fuer dein Benutzerkonto ^(ca. 25 MB, keine
echo  Administratorrechte noetig^). Das dauert ein bis zwei Minuten.
echo  Bitte dieses Fenster offen lassen, es geht danach von selbst weiter.
echo.
>>"%LOG%" echo %date% %time% start.bat: Python nicht gefunden, Installation wird versucht
set "ARCH=amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "ARCH=win32"
powershell -NoProfile -ExecutionPolicy Bypass -File "claudia\python_setup.ps1" -Arch %ARCH% -Log "%LOG%"
if not errorlevel 1 (
    >"%LOGDIR%\python_von_claudia_pyorg.txt" echo python.org
    echo.
    echo  Python ist installiert. CLAUDIA startet jetzt automatisch weiter.
    echo.
) else (
    >>"%LOG%" echo %date% %time% start.bat: Einrichtung von Python fehlgeschlagen
)
exit /b 0

:python_failed
echo.
echo  Python konnte nicht automatisch eingerichtet werden.
echo  Moegliche Ursachen: keine Internetverbindung, eine Firmen-Firewall oder
echo  ein Virenschutz blockiert den Download von python.org.
echo  Das Protokoll steht in: %LOG%
echo.
echo  Wenn sich das nicht beheben laesst, bitte Python von Hand installieren:
echo  https://www.python.org/downloads/  ^(im Installer "Add python.exe to PATH"
echo  ankreuzen^) und danach start.bat erneut doppelklicken.
echo.
pause
exit /b 1
