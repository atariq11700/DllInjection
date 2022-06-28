#include "NativeInjection.h"
#include "../utils/utils.h"
#include "../utils/log.h"

bool NativeInjection::inject(DWORD dwTargetPid, std::string dllpath) {
    //open target process
    HANDLE hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetPid);

    if (hTargetProc == INVALID_HANDLE_VALUE) {
        printfError("Unable to open target process\n");
        exit(1);
    }

    BYTEARRAY pDllBinaryDate = isValidDll(dllpath);
    if (!pDllBinaryDate) {
        CloseHandle(hTargetProc);
        exit(1);
    }
    delete[] pDllBinaryDate;

    //allocate memory inside target process for dll path cstring
    LPVOID addr = VirtualAllocEx(hTargetProc, 0, dllpath.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!addr) {
        printfError("Unable to allocate memory inside target process\n");
        exit(1);
    } else {
        printfInfo("Allocated %d bytes at 0x%llX\n", dllpath.size(), addr);
    }

    //write the dll path string to target process
    if (!WriteProcessMemory(hTargetProc, addr, dllpath.c_str(), dllpath.size(), nullptr)) {
        printfError("Unable to write dll path to target process\n");
    } else {
        printfInfo("Wrote dll path to target process\n");
    }

    //create a remote thread inside the target process and pass it ((LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"))(dllPathStringAddress)
    //aka the remote threads start function is LoadLibraryA(dllPathString);
    HANDLE hNewThread = CreateRemoteThreadEx(hTargetProc, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), addr, 0, 0, 0);

    if (hNewThread == INVALID_HANDLE_VALUE) {
        printfError("Unable to create a thread inside the target process\n");
        exit(1);
    } else {
        printfInfo("Created a remote thread inside the target process\n");
    }

    // CloseHandle(hNewThread);
    // CloseHandle(hTargetProc);

    return true;

}

void NativeInjection::printDescription() {
    printf("Native Injection:\n\t1. Alloc memory for the dll path using VirtualAllocEx\n\t2. Write the dll path using WriteProcessMemory\n\t3. Load the dll using CreateRemoteThreadEx\n");
}