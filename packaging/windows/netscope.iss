; Inno Setup script. Build with:  iscc /DAppVersion=1.0.0 packaging\windows\netscope.iss
; Expects the PyInstaller output in dist\NetScope\.
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{6F0B9C1E-3D5A-4C7B-9E21-4A7D2B1C8F30}
AppName=NetScope
AppVersion={#AppVersion}
AppPublisher=Andrew Gambucci
DefaultDirName={autopf}\NetScope
DefaultGroupName=NetScope
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\..\dist
OutputBaseFilename=NetScope-{#AppVersion}-windows-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\NetScope.exe
#ifexist "..\..\netscope\assets\icon.ico"
SetupIconFile=..\..\netscope\assets\icon.ico
#endif

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "..\..\dist\NetScope\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NetScope"; Filename: "{app}\NetScope.exe"
Name: "{autodesktop}\NetScope"; Filename: "{app}\NetScope.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\NetScope.exe"; Description: "Launch NetScope"; Flags: nowait postinstall skipifsilent

[Code]
// Windows can't capture packets without Npcap, so tell the user right away rather than
// letting live mode fail later.
function NpcapInstalled: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SOFTWARE\Npcap') or RegKeyExists(HKLM64, 'SOFTWARE\Npcap');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ErrorCode: Integer;
begin
  if (CurStep = ssPostInstall) and (not NpcapInstalled) then
    if MsgBox('NetScope needs the free Npcap packet-capture driver to show your live traffic. ' +
              'Open the Npcap download page now?' + #13#10 + #13#10 +
              'During its setup, keep "WinPcap API-compatible Mode" ticked.',
              mbInformation, MB_YESNO) = IDYES then
      ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
end;
