#include "payload_common.h"

int main(void)
{
    char hostPath[MAX_PATH];
    char message[512];

    hostPath[0] = '\0';
    GetModuleFileNameA(NULL, hostPath, MAX_PATH);
    PayloadWriteMarker("payload_exe");

    if (!PayloadUiDisabled()) {
        wsprintfA(message,
                  "payload_exe is now executing inside:\n%s\n\npid: %lu",
                  hostPath, GetCurrentProcessId());
        MessageBoxA(NULL, message, "Injection demo: process hollowing",
                    MB_OK | MB_ICONINFORMATION);
    }
    return 0;
}
