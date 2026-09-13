# Windows Process Injection PoC

A small educational proof-of-concept in C demonstrating two classic Windows process injection techniques:

- **Remote DLL injection** via `VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread`
- **Process hollowing** (RunPE-style) via `CreateProcess(CREATE_SUSPENDED)` / `NtUnmapViewOfSection` / `SetThreadContext` / `ResumeThread`

The payloads are intentionally benign: they append a line to `%TEMP%\injection_demo_marker.txt` and (unless silent mode is set) show a `MessageBox`. There is no shellcode, persistence, or evasion logic.

> **Authorized use only.** This is for security education, authorized red-team labs, and defensive research. Do not use it against systems you do not own or have permission to test. Do not target online games or third-party software; that violates terms of service and anti-cheat will ban you.

---

## Techniques

### 1. Remote DLL injection (`src/dll_injector.c`)

Makes a target process call `LoadLibrary` on an attacker-supplied DLL using only standard Windows APIs.

| Step | API | Purpose |
|------|-----|---------|
| 1 | `OpenProcess` | Get a handle with `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_VM_READ`, `PROCESS_QUERY_INFORMATION` |
| 2 | `VirtualAllocEx` | Reserve `PAGE_READWRITE` memory in the target for the DLL path |
| 3 | `WriteProcessMemory` | Copy the DLL path into that memory |
| 4 | Module snapshot + export offset | Resolve the address of `LoadLibraryA` **as mapped in the target**, by adding the local export offset to the target's `kernel32.dll` base |
| 5 | `CreateRemoteThread` | Start a thread whose start routine is `LoadLibraryA`, with the remote path buffer as its argument |
| 6 | `WaitForSingleObject` + `GetExitCodeThread` | Wait for `DllMain` to run; the returned `HMODULE` (0 = failure) confirms the load |

Why resolving `kernel32.dll` remotely matters: it is a KnownDLL, so in practice it is mapped at the same base in same-bitness processes. The tool still computes the remote base and offset rather than assuming, and falls back to the local address only if module enumeration fails.

### 2. Process hollowing (`src/process_hollow.c`)

Starts a legitimate process, replaces its in-memory image with a different executable, and lets the Windows loader initialize the swapped image.

| Step | API | Purpose |
|------|-----|---------|
| 1 | `CreateProcess(CREATE_SUSPENDED)` | Launch a decoy (e.g. `notepad.exe`) frozen before the app image is initialized |
| 2 | `NtQueryInformationProcess` + `ReadProcessMemory` | Read the remote PEB and its `ImageBaseAddress` |
| 3 | `NtUnmapViewOfSection` | Remove the decoy image from the address space |
| 4 | `VirtualAllocEx` | Re-allocate at the same base (`PAGE_EXECUTE_READWRITE`), falling back to any address if needed |
| 5 | `WriteProcessMemory` | Write the payload PE headers, then every section at its `VirtualAddress` |
| 6 | PEB update | If the image landed at a different base, update `PEB->ImageBaseAddress` so relocations resolve correctly |
| 7 | `GetThreadContext` / `SetThreadContext` | Point the start register (`RCX` on x64, `EAX` on x86) at `imageBase + AddressOfEntryPoint` |
| 8 | `ResumeThread` | The loader parses the new image, resolves its imports, and execution begins at the payload entry point |

The process keeps the decoy's identity (PID, name, token) while executing the payload's code.

---

## Project layout

```
src/
  dll_injector.c     Remote DLL injector (CreateRemoteThread + LoadLibraryA)
  process_hollow.c   Process hollowing loader
  payload_dll.c      Benign DLL payload (runs from DllMain)
  payload_exe.c      Benign EXE payload (runs from main)
  payload_common.h   Shared marker-file / UI helpers used by both payloads
  host.c             Do-nothing sleeper used as the test target
build.bat             MSVC build script (locates VS via vswhere, imports vcvars64)
test.bat              Automated end-to-end test with the benign payloads
```

Generated folders (not committed):

```
bin/     compiled executables and payload DLL
build/   intermediate .obj files
```

---

## Requirements

- Windows 10/11 x64
- Visual Studio 2019/2022/2026 with the **Desktop development with C++** workload
- A command prompt (batch scripts run anywhere; PowerShell not required)

## Build

```bat
build.bat
```

Produces in `bin\`:

- `dll_injector.exe`
- `process_hollow.exe`
- `payload.dll`
- `payload.exe`
- `host.exe`

All compile with `/W4 /O2` and no warnings.

---

## Usage

### DLL injection

```bat
bin\dll_injector.exe <pid|process-name> <path-to-dll>

rem examples
bin\dll_injector.exe notepad.exe bin\payload.dll
bin\dll_injector.exe 4308 bin\payload.dll
```

`LoadLibraryA` returns the remote module handle; non-zero means the DLL loaded and its `DllMain` ran.

### Process hollowing

```bat
bin\process_hollow.exe <decoy-executable> <payload-executable>

rem example
bin\process_hollow.exe C:\Windows\System32\notepad.exe bin\payload.exe
```

The decoy is started suspended, gutted, replaced with the payload image, and resumed.

### Modes

- Default: payloads show a `MessageBox` proving execution inside the target.
- **Silent mode:** `set INJECTION_DEMO_SILENT=1` skips the popup; the marker file is still written.

### Confirming it worked

- Marker file: `%TEMP%\injection_demo_marker.txt` — records payload name, host executable path, PID, and TID.
- Injected module: the DLL appears in the target's module list, e.g. `tasklist /m payload.dll`, or in Process Explorer.

---

## Automated test

```bat
test.bat
```

The script builds everything, then:

1. Starts `host.exe`, injects `payload.dll`, and asserts `payload_dll` ran inside it.
2. Hollows `host.exe` with `payload.exe` and asserts `payload_exe` ran inside it.
3. Cleans up the spawned processes.

Expected output:

```
[+] LoadLibraryA returned 0xE3A40000 inside pid 4308
[ok] payload_dll
     payload_dll executed | host=...\bin\host.exe | pid=4308 tid=23144
[+] hollowed pid=9540 imageBase=00007FF6B1B60000 entryPoint=00007FF6B1B616A0
[ok] payload_exe
     payload_exe executed | host=...\bin\host.exe | pid=9540 tid=23024
[+] all tests passed
```

---

## Relation to other tooling

| Term | Relationship |
|------|--------------|
| **LoadLibrary injection** | This project's `dll_injector.c` is the textbook implementation used by many external cheat injectors and loaders. |
| **Manual mapping** | One level stealthier: the DLL is mapped by hand, imports and relocations are fixed up manually, and the loader is never invoked, so the module does not appear in the module list. Not implemented here. |
| **Process hollowing** | Contemporary of manual mapping in the malware world (MITRE T1055.012); used to masquerade an arbitrary executable as a trusted process. |
| **Anti-cheat / EDR** | All of the above are detectable via remote-thread creation, unbacked executable memory, module-list anomalies, and image-to-disk mismatch. |

---

## Detection and mitigations

| Activity | Telemetry / detection |
|----------|----------------------|
| Process opening another for write + thread creation | Sysmon Event 10 (`ProcessAccess`), Event 8 (`CreateRemoteThread`) |
| Remote module load | Image-load ETW, module whose backing file is missing/odd, private executable memory |
| Process hollowing | Sysmon Event 25 (`ProcessTampering`), thread start address not in a known module, PEB image base vs on-disk image mismatch, initially-suspended child that never loads its own image |
| General | EDR memory scanning for `PAGE_EXECUTE_READWRITE` private regions, parent/child and token anomalies, `NtUnmapViewOfSection` on a live process image |

Defensive controls worth knowing: Windows Defender/EDR, ASR rules, Control Flow Guard, Arbitrary Code Guard and Code Integrity Guard on sensitive targets, Protected Process Light, and least-privilege tokens.

---

## Limitations and notes

- Injector and target must be the same architecture; the injector warns and aborts on a bitness mismatch.
- Remote `LoadLibraryA` resolution uses module enumeration with a local-address fallback.
- Hollowing requires a valid same-architecture PE; relocations should be available (default `/DYNAMICBASE`). If the image cannot be placed at its original base, the PEB image base is updated so the loader relocates correctly.
- Payloads that show a `MessageBox` keep the injector waiting until the box is closed, because the remote thread is still inside `DllMain`. This is expected.
- Security products may flag these binaries as hack tools. Run in a VM or an excluded lab directory.
- Windows 11's packaged Notepad works as a target too; the injected module and marker file confirm execution.

---

## References

- MITRE ATT&CK T1055 — Process Injection; T1055.001 — DLL Injection; T1055.012 — Process Hollowing
- *Windows Internals, 7th Edition* — Russinovich, Solomon, Ionescu
- Microsoft Learn — `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`, `NtUnmapViewOfSection`, `GetThreadContext`
