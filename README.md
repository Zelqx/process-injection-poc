# Windows Process Injection PoC

C proof-of-concept for two Windows injection techniques. The payloads are
benign: they append a line to `%TEMP%\injection_demo_marker.txt` and show a
`MessageBox` unless `INJECTION_DEMO_SILENT=1` is set.

- Remote DLL injection (`src/dll_injector.c`): `OpenProcess` ->
  `VirtualAllocEx` -> `WriteProcessMemory` ->
  `CreateRemoteThread(LoadLibraryA)`.
- Process hollowing (`src/process_hollow.c`): `CreateProcess(CREATE_SUSPENDED)`
  -> `NtUnmapViewOfSection` -> write the payload image -> `SetThreadContext`
  -> `ResumeThread`.

## Layout

```
src/dll_injector.c     remote DLL injector
src/process_hollow.c   process hollowing loader
src/payload_dll.c      benign DLL payload
src/payload_exe.c      benign EXE payload
src/payload_common.h   shared payload helpers
src/host.c             dummy target process
build.bat              MSVC build (vswhere + vcvars64)
test.bat               end-to-end test
```

Build output goes to `bin/` and `build/` (not committed).

## Build

```
build.bat
```

Produces `bin\dll_injector.exe`, `bin\process_hollow.exe`, `bin\payload.dll`,
`bin\payload.exe`, `bin\host.exe`. Needs Visual Studio with the C++ workload.

## Usage

```
bin\dll_injector.exe <pid|process-name> <path-to-dll>
bin\process_hollow.exe <decoy-executable> <payload-executable>
```

```
bin\dll_injector.exe notepad.exe bin\payload.dll
bin\process_hollow.exe C:\Windows\System32\notepad.exe bin\payload.exe
```

Success is confirmed by the marker file, or the module list for the DLL
(`tasklist /m payload.dll`).

## Test

```
test.bat
```

Builds everything, injects `payload.dll` into `host.exe`, hollows `host.exe`
with `payload.exe`, checks the marker file, and cleans up.

## Notes

- Injector and target must be the same architecture.
- Hollowing needs a same-architecture PE with relocations; if the image cannot
  load at its original base the PEB image base is updated so the loader
  relocates it.
- A payload that shows a `MessageBox` keeps the injector waiting until it is
  closed.
- Security products may flag these binaries. Run in a VM or an excluded lab
  directory.

## References

MITRE ATT&CK T1055 (.001 DLL injection, .012 process hollowing); *Windows
Internals, 7th Ed.*; Microsoft Learn for `CreateRemoteThread`,
`VirtualAllocEx`, `WriteProcessMemory`, `NtUnmapViewOfSection`,
`GetThreadContext`.
