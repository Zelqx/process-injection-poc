#include "payload_common.h"

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        PayloadWriteMarker("payload_dll");
        if (!PayloadUiDisabled())
            MessageBoxA(NULL,
                        "payload_dll was loaded inside this process.",
                        "Injection demo: DLL injection",
                        MB_OK | MB_ICONINFORMATION);
    }
    return TRUE;
}
