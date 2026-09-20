@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist obj mkdir obj
cl /nologo /W4 /WX /MT probe.c /Foobj\probe.obj /Feobj\probe.exe /link ws2_32.lib
exit /b %errorlevel%
