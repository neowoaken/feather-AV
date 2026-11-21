; feather installer
; Built with Inno Setup 6. Compile with:
;   "C:\Users\<you>\AppData\Local\Programs\Inno Setup 6\ISCC.exe" feather.iss

#define MyAppName "feather"
#define MyAppVersion "0.4.0"
#define MyAppPublisher "neowoaken"
#define MyAppURL "https://github.com/neowoaken/feather-AV"

[Setup]
AppId={{B3F2A1C4-9E7D-4F2B-8A1C-2D3E4F5A6B7C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=feather-setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\Feather.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut for the GUI"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: "addtopath"; Description: "Add feather to the system PATH (for the CLI)"; GroupDescription: "Command line:"; Flags: unchecked

[Files]
Source: "stage\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Feather"; Filename: "{app}\Feather.exe"; Comment: "feather desktop scanner"
Name: "{group}\Uninstall feather"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Feather"; Filename: "{app}\Feather.exe"; Tasks: desktopicon

; Inno Setup has no [Services] section: the helper repairs/recreates and starts
; FeatherRT, including on upgrades. The kernel filter is installed separately by
; driver\install-driver.ps1 because it needs test signing.

[Registry]
; Append {app} to the system PATH when requested.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
  ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
  Check: NeedsAddPath('{app}'); Tasks: addtopath

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  // Simple substring check; good enough for an installer.
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\install-service.ps1"" -Action install"; Flags: runhidden; StatusMsg: "Installing Feather real-time service..."
Filename: "{app}\Feather.exe"; Description: "Launch feather"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; sc.exe is always available; the staged helper may already be gone.
Filename: "{sys}\sc.exe"; Parameters: "stop FeatherRT"; Flags: runhidden; RunOnceId: "FeatherRTStop"
Filename: "{sys}\sc.exe"; Parameters: "delete FeatherRT"; Flags: runhidden; RunOnceId: "FeatherRTDelete"
