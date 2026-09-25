; Inno Setup script for the LogLens AI Windows installer (.exe).
; Produces LogLens-Setup-x64.exe from the PyInstaller onedir at dist\loglens\.
;
; Build (on Windows, with Inno Setup 6):
;   iscc /DMyAppVersion=0.12.0 packaging\windows\loglens.iss
;
; Installs to Program Files, adds loglens to PATH, and registers the warm daemon
; to start at logon so repeat runs are instant.

#ifndef MyAppVersion
  #define MyAppVersion "0.12.0"
#endif
#define MyAppName "LogLens AI"
#define MyAppExeName "loglens.exe"
#define MyAppPublisher "LogLens AI"
#define MyAppURL "https://github.com/LoglensAI/LogLens-AI"

[Setup]
AppId={{9F3B2C10-5D2E-4E7A-9E1B-LOGLENSAI0001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\LogLens
DefaultGroupName=LogLens AI
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=LogLens-Setup-x64
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
; SignTool=... ; add a code-signing cert here to avoid SmartScreen warnings

[Files]
; The whole PyInstaller onedir (dist\loglens\*) goes under {app}\loglens\
Source: "..\..\dist\loglens\*"; DestDir: "{app}\loglens"; Flags: recursesubdirs createallsubdirs

[Tasks]
Name: "addtopath"; Description: "Add loglens to PATH"; GroupDescription: "Integration:"
Name: "startdaemon"; Description: "Start the warm daemon at logon (faster runs)"; GroupDescription: "Integration:"

[Registry]
; Add {app}\loglens to the user PATH when the task is selected.
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}\loglens"; Tasks: addtopath; \
  Check: NeedsAddPath(ExpandConstant('{app}\loglens'))
; Auto-start the daemon at logon.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
  ValueType: string; ValueName: "LogLensDaemon"; \
  ValueData: """{app}\loglens\{#MyAppExeName}"" daemon start"; Tasks: startdaemon

[Icons]
Name: "{group}\LogLens (help)"; Filename: "{app}\loglens\{#MyAppExeName}"; Parameters: "help"

[Run]
Filename: "{app}\loglens\{#MyAppExeName}"; Parameters: "daemon start"; \
  Flags: nowait runhidden; Tasks: startdaemon

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
