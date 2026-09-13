#ifndef PAYLOAD_COMMON_H
#define PAYLOAD_COMMON_H

#include <windows.h>

static BOOL PayloadUiDisabled(void)
{
    char value[8];
    DWORD length = GetEnvironmentVariableA("INJECTION_DEMO_SILENT", value, sizeof(value));
    return length > 0 && value[0] == '1';
}

static void PayloadWriteMarker(const char *payloadName)
{
    char tempPath[MAX_PATH];
    char markerPath[MAX_PATH];
    char hostPath[MAX_PATH];
    char message[512];
    HANDLE file;
    DWORD written = 0;
    int length;

    if (GetTempPathA(MAX_PATH, tempPath) == 0)
        return;

    lstrcpynA(markerPath, tempPath, MAX_PATH);
    lstrcatA(markerPath, "injection_demo_marker.txt");

    hostPath[0] = '\0';
    GetModuleFileNameA(NULL, hostPath, MAX_PATH);

    file = CreateFileA(markerPath, FILE_APPEND_DATA,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return;

    length = wsprintfA(message,
                       "%s executed | host=%s | pid=%lu tid=%lu\r\n",
                       payloadName, hostPath,
                       GetCurrentProcessId(), GetCurrentThreadId());
    WriteFile(file, message, (DWORD)length, &written, NULL);
    CloseHandle(file);
}

#endif
