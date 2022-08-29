#include <iostream>
#include <windows.h>
#include <time.h>

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved ) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            
            FILE* file;
            
            AllocConsole();
            freopen_s(&file, "CONIN$", "w", stdin);
            freopen_s(&file, "CONOUT$", "w", stdout);
            freopen_s(&file, "CONOUT$", "w", stderr);


            std::cout << "Hello From DLL\n";
            //Sleep(2000);
            //exit(0);
        };
        break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}