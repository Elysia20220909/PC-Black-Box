@echo off
setlocal
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "PCBB_VS=%%i"
if not defined PCBB_VS exit /b 1
call "%PCBB_VS%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist obj mkdir obj
cl /nologo /W4 /WX /MT probe.c /Foobj\probe.obj /Feobj\probe.exe /link ws2_32.lib
exit /b %errorlevel%
