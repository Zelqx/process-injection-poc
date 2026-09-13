@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
pushd "%ROOT%"

set "INJECTION_DEMO_SILENT=1"
set "MARKER=%TEMP%\injection_demo_marker.txt"
set "HOLLOWOUT=%TEMP%\injection_demo_hollow_output.txt"

call "%ROOT%build.bat"
if errorlevel 1 (
    echo [-] build failed
    goto :fail
)

echo.
echo [*] test 1: DLL injection (OpenProcess -^> VirtualAllocEx -^> WriteProcessMemory -^> CreateRemoteThread)
del "%MARKER%" >nul 2>&1
start "" /b bin\host.exe
ping -n 2 127.0.0.1 >nul
bin\dll_injector.exe host.exe bin\payload.dll
if errorlevel 1 (
    echo [-] dll_injector.exe failed
    taskkill /f /im host.exe >nul 2>&1
    goto :fail
)

if not exist "%MARKER%" (
    echo [-] marker file was not created
    taskkill /f /im host.exe >nul 2>&1
    goto :fail
)
findstr /c:"payload_dll" "%MARKER%" >nul
if errorlevel 1 (
    echo [-] payload_dll marker line not found
    taskkill /f /im host.exe >nul 2>&1
    goto :fail
)
echo [ok] payload_dll
findstr /c:"payload_dll" "%MARKER%"
taskkill /f /im host.exe >nul 2>&1

echo.
echo [*] test 2: process hollowing (CreateProcess suspended -^> NtUnmapViewOfSection -^> VirtualAllocEx -^> SetThreadContext -^> ResumeThread)
del "%MARKER%" >nul 2>&1
bin\process_hollow.exe bin\host.exe bin\payload.exe > "%HOLLOWOUT%"
if errorlevel 1 (
    type "%HOLLOWOUT%"
    echo [-] process_hollow.exe failed
    goto :fail
)
type "%HOLLOWOUT%"

set "HPID="
for /f "usebackq tokens=3" %%p in ("%HOLLOWOUT%") do set "HPID=%%p" 2>nul
if defined HPID set "HPID=!HPID:pid=!"

ping -n 2 127.0.0.1 >nul
if not exist "%MARKER%" (
    echo [-] marker file was not created
    goto :fail
)
findstr /c:"payload_exe" "%MARKER%" >nul
if errorlevel 1 (
    echo [-] payload_exe marker line not found
    goto :fail
)
echo [ok] payload_exe
findstr /c:"payload_exe" "%MARKER%"
if defined HPID taskkill /f /pid !HPID! >nul 2>&1

del "%HOLLOWOUT%" >nul 2>&1
echo.
echo [+] all tests passed
popd
exit /b 0

:fail
del "%HOLLOWOUT%" >nul 2>&1
popd
exit /b 1
