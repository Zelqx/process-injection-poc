#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

static DWORD FindProcessIdByName(const char *name)
{
    HANDLE snapshot;
    PROCESSENTRY32 entry;
    DWORD pid = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    entry.dwSize = sizeof(entry);
    if (Process32First(snapshot, &entry)) {
        do {
            if (lstrcmpiA(entry.szExeFile, name) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

static int GetProcessBitness(HANDLE process)
{
    typedef BOOL (WINAPI *PFN_IsWow64Process)(HANDLE, PBOOL);
    PFN_IsWow64Process isWow64Process;
    BOOL isWow64 = FALSE;

    isWow64Process = (PFN_IsWow64Process)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "IsWow64Process");
    if (isWow64Process == NULL || !isWow64Process(process, &isWow64))
        return -1;

    return isWow64 ? 32 : 64;
}

static HMODULE FindRemoteModuleBase(DWORD pid, const char *moduleName)
{
    HANDLE snapshot;
    MODULEENTRY32 entry;
    HMODULE base = NULL;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
        return NULL;

    entry.dwSize = sizeof(entry);
    if (Module32First(snapshot, &entry)) {
        do {
            if (lstrcmpiA(entry.szModule, moduleName) == 0) {
                base = entry.hModule;
                break;
            }
        } while (Module32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return base;
}

static LPTHREAD_START_ROUTINE ResolveRemoteLoadLibraryA(DWORD pid)
{
    HMODULE localKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC localLoadLibraryA = GetProcAddress(localKernel32, "LoadLibraryA");
    HMODULE remoteKernel32 = FindRemoteModuleBase(pid, "kernel32.dll");

    if (localKernel32 == NULL || localLoadLibraryA == NULL)
        return NULL;

    if (remoteKernel32 == NULL)
        return (LPTHREAD_START_ROUTINE)localLoadLibraryA;

    return (LPTHREAD_START_ROUTINE)((BYTE *)remoteKernel32 +
        ((BYTE *)localLoadLibraryA - (BYTE *)localKernel32));
}

int main(int argc, char **argv)
{
    char dllPath[MAX_PATH];
    char *end = NULL;
    DWORD pid;
    DWORD parsedPid;
    HANDLE process;
    LPVOID remoteBuffer;
    LPTHREAD_START_ROUTINE remoteLoadLibraryA;
    HANDLE remoteThread;
    SIZE_T pathSize;
    DWORD exitCode = 0;
    int injectorBitness;
    int targetBitness;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <pid|process-name> <path-to-dll>\n", argv[0]);
        return 1;
    }

    if (GetFullPathNameA(argv[2], MAX_PATH, dllPath, NULL) == 0 ||
        GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[-] DLL not found: %s\n", argv[2]);
        return 1;
    }

    parsedPid = (DWORD)strtoul(argv[1], &end, 10);
    if (end != argv[1] && *end == '\0' && parsedPid != 0)
        pid = parsedPid;
    else
        pid = FindProcessIdByName(argv[1]);

    if (pid == 0) {
        fprintf(stderr, "[-] no target process matched '%s'\n", argv[1]);
        return 1;
    }

    process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                          PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                          FALSE, pid);
    if (process == NULL) {
        fprintf(stderr, "[-] OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return 1;
    }

    injectorBitness = GetProcessBitness(GetCurrentProcess());
    targetBitness = GetProcessBitness(process);
    if (injectorBitness > 0 && targetBitness > 0 && injectorBitness != targetBitness) {
        fprintf(stderr, "[-] bitness mismatch: injector=%d-bit target=%d-bit\n",
                injectorBitness, targetBitness);
        CloseHandle(process);
        return 1;
    }

    pathSize = (SIZE_T)lstrlenA(dllPath) + 1;
    remoteBuffer = VirtualAllocEx(process, NULL, pathSize,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteBuffer == NULL) {
        fprintf(stderr, "[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(process);
        return 1;
    }

    if (!WriteProcessMemory(process, remoteBuffer, dllPath, pathSize, NULL)) {
        fprintf(stderr, "[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    remoteLoadLibraryA = ResolveRemoteLoadLibraryA(pid);
    if (remoteLoadLibraryA == NULL) {
        fprintf(stderr, "[-] unable to resolve LoadLibraryA in the target\n");
        VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    remoteThread = CreateRemoteThread(process, NULL, 0, remoteLoadLibraryA,
                                      remoteBuffer, 0, NULL);
    if (remoteThread == NULL) {
        fprintf(stderr, "[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    WaitForSingleObject(remoteThread, INFINITE);
    GetExitCodeThread(remoteThread, &exitCode);

    VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(remoteThread);
    CloseHandle(process);

    if (exitCode == 0) {
        fprintf(stderr, "[-] target failed to load the DLL (LoadLibraryA returned NULL)\n");
        return 1;
    }

    printf("[+] LoadLibraryA returned 0x%08lX inside pid %lu\n",
           (unsigned long)exitCode, pid);
    return 0;
}
