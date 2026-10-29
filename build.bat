@echo off
rem Usage: build.bat [x64|x86]   (default: x64)
rem Output: opm_hdcp_force_<arch>.exe
setlocal

set ARCH=%1
if "%ARCH%"=="" set ARCH=x64
if /i "%ARCH%"=="x64" goto arch_ok
if /i "%ARCH%"=="x86" goto arch_ok
echo usage: build.bat [x64^|x86]
exit /b 1
:arch_ok

rem Already in a Developer Command Prompt (or CI with the toolchain set up)?
where cl >nul 2>&1
if not errorlevel 1 goto build

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto no_vs
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR goto no_vs
call "%VSDIR%\VC\Auxiliary\Build\vcvarsall.bat" %ARCH%
if errorlevel 1 exit /b 1

:build
cl /nologo /EHsc /W4 /Fe:opm_hdcp_force_%ARCH%.exe opm_hdcp_force.cpp /link dxva2.lib d3d9.lib bcrypt.lib crypt32.lib user32.lib ole32.lib
exit /b %errorlevel%

:no_vs
echo Visual Studio (C++ build tools) not found. Run this from a Developer Command Prompt.
exit /b 1
