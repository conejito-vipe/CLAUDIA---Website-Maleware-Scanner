; Inno-Setup-Skript für CLAUDIA: Installation nur für den aktuellen Benutzer, ohne Administratorrechte.
; Ziel: %LOCALAPPDATA%\Programs\CLAUDIA. Gepackt wird das entpackte Release-Paket (dist\CLAUDIA, vom Workflow erzeugt).
; Beim ersten Start richtet start.bat Python und die Bausteine selbst ein (Ordner .venv im Programmordner).
; Persönliche Daten (Verbindungen, Einstellungen, Berichte) liegen in %APPDATA%\CLAUDIA und werden bei Update
; und Deinstallation nie angefasst. Die Funktion "CLAUDIA deinstallieren" im Programm bleibt für die Datenbereinigung.
; Zwei Arten (der Workflow .github/workflows/release.yml baut die zweite):
;   - ohne Angabe:           Release-Paket (dist\CLAUDIA), start.bat richtet Python beim ersten Start selbst ein
;   - mit /DFrozenApp=1:     einzelne Programmdatei CLAUDIA.exe samt Bausteinen (dist-exe\_work\dist\CLAUDIA), keine Python-Einrichtung
; Hinweis: SmartScreen zeigt einen Herausgeber nur bei signierten Dateien (siehe README).

#define AppShortName "CLAUDIA"
#ifndef AppVersion
  #define AppVersion "3.1.0"
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
WizardResizable=yes
OutputDir=Output
OutputBaseFilename=CLAUDIA-Setup-{#AppVersion}
LicenseFile=..\LICENSE
SetupIconFile=..\claudia\assets\claudia.ico
WizardImageFile=wizard.bmp
WizardSmallImageFile=wizard_small.bmp
UninstallDisplayName={#AppShortName}
#ifdef FrozenApp
UninstallDisplayIcon={app}\CLAUDIA.exe
#else
UninstallDisplayIcon={app}\claudia\assets\claudia.ico
#endif
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
#ifdef FrozenApp
; Wechsel von der Python-Fassung: alte Startdateien und die eigene Python-Umgebung entfernen (Nutzerdaten liegen in %APPDATA%\CLAUDIA)
Type: filesandordirs; Name: "{app}\.venv"
Type: files; Name: "{app}\start.bat"
Type: files; Name: "{app}\start.command"
Type: files; Name: "{app}\install.command"
Type: files; Name: "{app}\pruefen.bat"
#endif

[Files]
Source: "hinweis_smartscreen.bmp"; DestDir: "{tmp}"; Flags: dontcopy
#ifdef FrozenApp
Source: "..\dist-exe\_work\dist\CLAUDIA\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
#else
Source: "..\dist\CLAUDIA\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
#endif

[Icons]
#ifdef FrozenApp
Name: "{autoprograms}\{#AppShortName}"; Filename: "{app}\CLAUDIA.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\{#AppShortName}"; Filename: "{app}\CLAUDIA.exe"; WorkingDir: "{app}"; Tasks: desktopicon
#else
Name: "{autoprograms}\{#AppShortName}"; Filename: "{app}\start.bat"; WorkingDir: "{app}"; IconFilename: "{app}\claudia\assets\claudia.ico"
Name: "{autodesktop}\{#AppShortName}"; Filename: "{app}\start.bat"; WorkingDir: "{app}"; IconFilename: "{app}\claudia\assets\claudia.ico"; Tasks: desktopicon
#endif

[Run]
#ifdef FrozenApp
Filename: "{app}\CLAUDIA.exe"; WorkingDir: "{app}"; Description: "{cm:LaunchProgram,{#AppShortName}}"; Flags: nowait postinstall skipifsilent
#else
Filename: "{app}\start.bat"; WorkingDir: "{app}"; Description: "{cm:LaunchProgram,{#AppShortName}}"; Flags: nowait postinstall skipifsilent shellexec
#endif

[UninstallDelete]
Type: filesandordirs; Name: "{app}\.venv"
Type: files; Name: "{app}\CLAUDIA.lnk"

[CustomMessages]
german.SmartTitle=Windows-Meldung beim Start
german.SmartSub=Warum Windows warnt und was du tun kannst
german.SmartText=CLAUDIA ist ein kostenloses Programm ohne Herstellerzertifikat. Deshalb kann Windows (Microsoft Defender SmartScreen) beim ersten Start die Meldung „Der Computer wurde durch Windows geschützt“ anzeigen. Das liegt am fehlenden Zertifikat, nicht an einem Fund.%n%nSo geht es weiter: Klicke auf „Weitere Informationen“ (falls sichtbar) und dann auf „Trotzdem ausführen“. Der Quelltext ist offen einsehbar: github.com/conejito-vipe.
english.SmartTitle=Windows message at start
english.SmartSub=Why Windows warns and what you can do
english.SmartText=CLAUDIA is a free program without a publisher certificate. Therefore Windows (Microsoft Defender SmartScreen) may show the message "Windows protected your PC" when it starts for the first time. This is due to the missing certificate, not to a finding.%n%nTo continue: click "More info" (if shown) and then "Run anyway". The source code is open: github.com/conejito-vipe.
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

function ReadInstalledVersion(var Old: String): Boolean;
var Text, Rest: AnsiString; P, Q: Integer; Old2: String;
begin
  Result := RegQueryStringValue(HKCU, UninstKey, 'DisplayVersion', Old) or
            RegQueryStringValue(HKLM, UninstKey, 'DisplayVersion', Old);
  if Result then Exit;
  { Ohne Registry-Eintrag (z. B. Python-Fassung oder Kopie im Programmordner): Version aus claudia\__init__.py lesen }
  Result := False;
  if LoadStringFromFile(ExpandConstant('{localappdata}\Programs\CLAUDIA\claudia\__init__.py'), Text) then
  begin
    P := Pos('__version__', Text);
    if P > 0 then
    begin
      Rest := Copy(Text, P, 200);
      P := Pos('"', Rest);
      if P > 0 then
      begin
        Delete(Rest, 1, P);
        Q := Pos('"', Rest);
        if Q > 0 then begin Old2 := Copy(Rest, 1, Q - 1); Old := Old2; Result := Old <> ''; end;
      end;
    end;
  end;
end;

procedure InitializeWizard;
var Pg: TWizardPage; Txt: TNewStaticText; Pic: TBitmapImage;
begin
  { Hinweis zur Windows-Meldung: nach der Installation, vor der letzten Seite }
  Pg := CreateCustomPage(wpInstalling, CustomMessage('SmartTitle'), CustomMessage('SmartSub'));
  Pic := TBitmapImage.Create(Pg);
  Pic.Parent := Pg.Surface;
  Pic.Stretch := True;
  Pic.Left := ScaleX(300); Pic.Top := ScaleY(0);
  Pic.Width := ScaleX(250); Pic.Height := ScaleY(234);
  ExtractTemporaryFile('hinweis_smartscreen.bmp');
  Pic.Bitmap.LoadFromFile(ExpandConstant('{tmp}\hinweis_smartscreen.bmp'));
  Txt := TNewStaticText.Create(Pg);
  Txt.Parent := Pg.Surface;
  Txt.Left := 0; Txt.Top := 0;
  Txt.Width := ScaleX(285); Txt.AutoSize := False; Txt.WordWrap := True;
  Txt.Height := ScaleY(260);
  Txt.Caption := StringChange(CustomMessage('SmartText'), '%n', #13#10);
end;

function InitializeSetup(): Boolean;
var Old, Msg: String; C: Integer;
begin
  Result := True;
  if not ReadInstalledVersion(Old) then Exit;
  if WizardSilent then Exit;
  C := CompareVer(Old, '{#AppVersion}');
  if C < 0 then Msg := FmtMessage(CustomMessage('UpdateAsk'), [Old, '{#AppVersion}'])
  else if C = 0 then Msg := FmtMessage(CustomMessage('SameAsk'), [Old])
  else Msg := FmtMessage(CustomMessage('OlderAsk'), [Old, '{#AppVersion}']);
  Result := MsgBox(Msg, mbConfirmation, MB_YESNO) = IDYES;
end;
