; Inno-Setup-Skript für CLAUDIA: Installation nur für den aktuellen Benutzer, ohne Administratorrechte.
; Ziel: %LOCALAPPDATA%\Programs\CLAUDIA. Gepackt wird das entpackte Release-Paket (dist\CLAUDIA, vom Workflow erzeugt).
; Beim ersten Start richtet start.bat Python und die Bausteine selbst ein (Ordner .venv im Programmordner).
; Persönliche Daten (Verbindungen, Einstellungen, Berichte) liegen in %APPDATA%\CLAUDIA und werden bei Update
; und Deinstallation nie angefasst. Die Funktion "CLAUDIA deinstallieren" im Programm bleibt für die Datenbereinigung.
; Hinweis: SmartScreen zeigt einen Herausgeber nur bei signierten Dateien (siehe README).

#define AppShortName "CLAUDIA"
#ifndef AppVersion
  #define AppVersion "2.15.0"
#endif
#define AuthorName "conejito-vipe"

[Setup]
AppId={{B7C3E9A2-5D41-4F6B-8A17-3C9D2E6F0B54}
AppName={#AppShortName}
AppVersion={#AppVersion}
AppPublisher=GitHub - {#AuthorName}
AppPublisherURL=https://github.com/{#AuthorName}
AppCopyright=Copyright (c) 2026 {#AuthorName}
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany={#AuthorName}
VersionInfoDescription={#AppShortName} Setup
VersionInfoProductName={#AppShortName}
DefaultDirName={localappdata}\Programs\{#AppShortName}
DefaultGroupName={#AppShortName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
OutputDir=Output
OutputBaseFilename=CLAUDIA-Setup-{#AppVersion}
LicenseFile=..\LICENSE
SetupIconFile=..\claudia\assets\claudia.ico
UninstallDisplayName={#AppShortName}
UninstallDisplayIcon={app}\claudia\assets\claudia.ico
CloseApplications=no

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"; LicenseFile: "..\LIZENZ.txt"
Name: "english"; MessagesFile: "compiler:Default.isl"; LicenseFile: "..\LICENSE"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[InstallDelete]
; Programmcode der alten Version entfernen; .venv und Nutzerdaten bleiben erhalten.
Type: filesandordirs; Name: "{app}\claudia"
Type: filesandordirs; Name: "{app}\tests"
Type: filesandordirs; Name: "{app}\tools"

[Files]
Source: "..\dist\CLAUDIA\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\{#AppShortName}"; Filename: "{app}\start.bat"; WorkingDir: "{app}"; IconFilename: "{app}\claudia\assets\claudia.ico"
Name: "{autodesktop}\{#AppShortName}"; Filename: "{app}\start.bat"; WorkingDir: "{app}"; IconFilename: "{app}\claudia\assets\claudia.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\start.bat"; WorkingDir: "{app}"; Description: "{cm:LaunchProgram,{#AppShortName}}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallDelete]
Type: filesandordirs; Name: "{app}\.venv"
Type: files; Name: "{app}\CLAUDIA.lnk"

[CustomMessages]
german.UpdateAsk=CLAUDIA %1 ist bereits installiert. Die neue Version ist %2.%nSoll auf %2 aktualisiert werden? Deine Verbindungen, Einstellungen und Berichte bleiben erhalten.
english.UpdateAsk=CLAUDIA %1 is already installed. The new version is %2.%nUpdate to %2? Your connections, settings and reports are kept.
german.SameAsk=CLAUDIA %1 ist bereits installiert.%nSoll sie neu installiert (repariert) werden? Deine Daten bleiben erhalten.
english.SameAsk=CLAUDIA %1 is already installed.%nReinstall (repair) it? Your data is kept.
german.OlderAsk=Es ist bereits eine NEUERE Version (%1) installiert als diese (%2).%nTrotzdem auf %2 zurückstellen? Deine Daten bleiben erhalten.
english.OlderAsk=A NEWER version (%1) is already installed than this one (%2).%nDowngrade to %2 anyway? Your data is kept.

[Code]
const
  UninstKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{B7C3E9A2-5D41-4F6B-8A17-3C9D2E6F0B54}_is1';

function VerPart(var S: String): Integer;
var P: Integer;
begin
  P := Pos('.', S);
  if P = 0 then begin Result := StrToIntDef(S, 0); S := ''; end
  else begin Result := StrToIntDef(Copy(S, 1, P - 1), 0); Delete(S, 1, P); end;
end;

function CompareVer(A, B: String): Integer;
var I, X, Y: Integer;
begin
  Result := 0;
  for I := 1 to 4 do
  begin
    X := VerPart(A); Y := VerPart(B);
    if X < Y then begin Result := -1; Exit; end;
    if X > Y then begin Result := 1; Exit; end;
  end;
end;

function InitializeSetup(): Boolean;
var Old, Msg: String; C: Integer;
begin
  Result := True;
  if not (RegQueryStringValue(HKCU, UninstKey, 'DisplayVersion', Old) or
          RegQueryStringValue(HKLM, UninstKey, 'DisplayVersion', Old)) then Exit;
  if WizardSilent then Exit;
  C := CompareVer(Old, '{#AppVersion}');
  if C < 0 then Msg := FmtMessage(CustomMessage('UpdateAsk'), [Old, '{#AppVersion}'])
  else if C = 0 then Msg := FmtMessage(CustomMessage('SameAsk'), [Old])
  else Msg := FmtMessage(CustomMessage('OlderAsk'), [Old, '{#AppVersion}']);
  Result := MsgBox(Msg, mbConfirmation, MB_YESNO) = IDYES;
end;
