@echo off
setlocal

set "ROOT=%~dp0"
pushd "%ROOT%"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [-] vswhere.exe not found; install Visual Studio with the C++ workload
    goto :fail
)

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo [-] Visual Studio C++ build tools not found
    goto :fail
)

set "VCVARS=%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo [-] vcvars64.bat not found at "%VCVARS%"
    goto :fail
)

call "%VCVARS%" >nul 2>&1
if errorlevel 1 (
    echo [-] failed to initialize the MSVC environment
    goto :fail
)

if not exist "bin" mkdir bin
if not exist "build" mkdir build

set "CFLAGS=/nologo /W4 /O2 /Fo:build\\"

echo [*] dll_injector.exe
cl %CFLAGS% /Fe:bin\dll_injector.exe src\dll_injector.c
if errorlevel 1 goto :fail

echo [*] payload.dll
cl %CFLAGS% /LD /Fe:bin\payload.dll src\payload_dll.c /link /NOIMPLIB /NOEXP user32.lib
if errorlevel 1 goto :fail

echo [*] process_hollow.exe
cl %CFLAGS% /Fe:bin\process_hollow.exe src\process_hollow.c
if errorlevel 1 goto :fail

echo [*] payload.exe
cl %CFLAGS% /Fe:bin\payload.exe src\payload_exe.c /link user32.lib
if errorlevel 1 goto :fail

echo [*] host.exe
cl %CFLAGS% /Fe:bin\host.exe src\host.c
if errorlevel 1 goto :fail

echo [+] build complete
popd
exit /b 0

:fail
popd
exit /b 1
