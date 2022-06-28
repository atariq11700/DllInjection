#include "ManualMap.h"
#include "../utils/utils.h"
#include "../utils/log.h"



typedef HINSTANCE   (WINAPI*    f_LoadLibraryA)     (const char* lpLibraryFilename);
typedef FARPROC     (WINAPI*    f_GetProcAddress)   (HMODULE hModule, LPCSTR lpProcName);
typedef BOOL        (APIENTRY*  f_DllMain)          (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

typedef struct _ManualMapLoaderData {
    f_LoadLibraryA      pLoadLibraryA;
    f_GetProcAddress    pGetProcAddress;
    HINSTANCE           pDllBaseAddr;
} ManualMapLoaderData, *pManualMapLoaderData;

typedef struct _RelocationEntry {
    DWORD dwPageRVA;
    DWORD dwBlockSize;
    struct {
        WORD offset : 12;
        WORD type : 4;
    } items[1];
} RelocationEntry, *pRelocationEntry;

void __stdcall loader(ManualMapLoaderData* pmmData);


bool ManualMap::inject(DWORD dwTargetPid, std::string dllpath) {
    const char* szDllPath = dllpath.c_str();

    //open target process
    HANDLE hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, false, dwTargetPid);

    if (hTargetProc == INVALID_HANDLE_VALUE) {
        printfError("Unable to open target process\n");
        CloseHandle(hTargetProc);
        exit(1);
    }

    BYTEARRAY pDllBinaryData = isValidDll(dllpath);

    if (!pDllBinaryData) {
        CloseHandle(hTargetProc);
        exit(1);
    }


    //get image headers
    IMAGE_NT_HEADERS*       pDllNtHeader    =   (IMAGE_NT_HEADERS*)(pDllBinaryData + ((IMAGE_DOS_HEADER*)pDllBinaryData)->e_lfanew);
    IMAGE_OPTIONAL_HEADER*  pDllOptHeader   =   (IMAGE_OPTIONAL_HEADER*)&pDllNtHeader->OptionalHeader;
    IMAGE_FILE_HEADER*      pDllFileHeader  =   (IMAGE_FILE_HEADER*)&pDllNtHeader->FileHeader;


    
    //allocate memory inside the target process for our dll image
    BYTE* pTargetBaseAddr;
    pTargetBaseAddr = (BYTE*)VirtualAllocEx(hTargetProc, (LPVOID)pDllOptHeader->ImageBase, pDllOptHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!pTargetBaseAddr) {
        pTargetBaseAddr = (BYTE*)VirtualAllocEx(hTargetProc, NULL, pDllOptHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pTargetBaseAddr) {
            printfError("Unable to allocate memory inside of target process for dll\n");
            CloseHandle(hTargetProc);
            delete[] pDllBinaryData;
            exit(1);
        }
    }

    printfInfo("Allocated %d bytes at 0x%llX inside target process for dll\n", pDllOptHeader->SizeOfImage, pTargetBaseAddr);

    IMAGE_SECTION_HEADER* pDllSectionHeader = IMAGE_FIRST_SECTION(pDllNtHeader);

    //enumerate all the sections in the image header, if the section has initialized data, map it into the target process
    //write to target at the mapped dll base addr + the virutal address offset of the section, write from our local dll buffer + the pointer to the data offset, write the size of raw data bytes
    for (int i = 0; i < pDllFileHeader->NumberOfSections; i++) {
        if (pDllSectionHeader->SizeOfRawData) {
            BOOL memWriteStatus = WriteProcessMemory(
                hTargetProc, 
                pTargetBaseAddr + pDllSectionHeader->VirtualAddress, 
                pDllBinaryData + pDllSectionHeader->PointerToRawData, 
                pDllSectionHeader->SizeOfRawData, 
                nullptr
            );

            if (!memWriteStatus) {
                printfError("Unable to map section %s into target process memory\n", pDllSectionHeader->Name);
                CloseHandle(hTargetProc);
                VirtualFreeEx(hTargetProc, pTargetBaseAddr, pDllOptHeader->SizeOfImage, MEM_FREE);
                delete[] pDllBinaryData;
                exit(1);
            } else {
                printfInfo("Mapped dll section %-8s (%-5d bytes) to target process at 0x%llX\n", pDllSectionHeader->Name, pDllSectionHeader->SizeOfRawData, pTargetBaseAddr + pDllSectionHeader->VirtualAddress);
            }
        }
        pDllSectionHeader++;
    }

    //write the pe headers
    WriteProcessMemory(hTargetProc, pTargetBaseAddr, pDllBinaryData, 0x1000, nullptr);
    printfInfo("Wrote the pe headers to the base addr inside the target process at 0x%llX\n", pTargetBaseAddr);


    delete[] pDllBinaryData;


    //setup loader data
    ManualMapLoaderData loaderData {0};
    loaderData.pLoadLibraryA = LoadLibraryA;
    loaderData.pGetProcAddress = GetProcAddress;
    loaderData.pDllBaseAddr = (HINSTANCE)pTargetBaseAddr;

    //write loader data at base addr
    WriteProcessMemory(hTargetProc, pTargetBaseAddr, &loaderData, sizeof(ManualMapLoaderData), nullptr);
    printfInfo("Wrote the loader data to the base addr inside the target process at 0x%llX\n", pTargetBaseAddr);

    //allocate memory for loader function
    BYTE* pLoader = (BYTE*)VirtualAllocEx(hTargetProc, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pLoader) {
        printfError("Unable to allocate memory inside of target process for loader function\n");
        CloseHandle(hTargetProc);
        VirtualFreeEx(hTargetProc, pTargetBaseAddr, pDllOptHeader->SizeOfImage, MEM_FREE);
        exit(1);
    } else {
        printfInfo("Allocated %d bytes at 0x%llX inside the target process for the loader function\n", 0x1000, pLoader);
    }

    //write loader function
    WriteProcessMemory(hTargetProc, pLoader, (LPVOID)loader, 0x1000, nullptr);
    printfInfo("Wrote %d bytes of the loader function to 0x%llX inside the target process\n", 0x1000, pLoader);

    if (CreateRemoteThreadEx(hTargetProc, NULL, 0 , (LPTHREAD_START_ROUTINE)pLoader, pTargetBaseAddr, 0, 0, 0) == INVALID_HANDLE_VALUE) {
        printfError("Unable to create remote thread calling loader\n");
        CloseHandle(hTargetProc);
        VirtualFreeEx(hTargetProc, pTargetBaseAddr, pDllOptHeader->SizeOfImage, MEM_FREE);
        exit(1);
    } else {
        printfSucc("Created a remote thread inside the target process\n");
    }


    return true;

}

void __stdcall loader(ManualMapLoaderData* pmmData) {
    if (!pmmData) {
        return;
    }

    f_LoadLibraryA _LoadLibraryA = pmmData->pLoadLibraryA;
    f_GetProcAddress _GetProcAddress = pmmData->pGetProcAddress;
    BYTE* pBaseAddr = (BYTE*)pmmData;

     //get image headers
    IMAGE_NT_HEADERS*       pDllNtHeader    =   (IMAGE_NT_HEADERS*)(pBaseAddr + ((IMAGE_DOS_HEADER*)pBaseAddr)->e_lfanew);
    IMAGE_OPTIONAL_HEADER*  pDllOptHeader   =   (IMAGE_OPTIONAL_HEADER*)&pDllNtHeader->OptionalHeader;
    IMAGE_FILE_HEADER*      pDllFileHeader  =   (IMAGE_FILE_HEADER*)&pDllNtHeader->FileHeader;

    f_DllMain _DllMain = (f_DllMain)(pDllOptHeader->AddressOfEntryPoint + pBaseAddr);

    uint64_t locationDelta = (ULONGLONG)pBaseAddr - pDllOptHeader->ImageBase;

    if (locationDelta) {
    }





}

void ManualMap::printDescription() {
    printf("Manual Map:\n\t1. Load DLL binary data\n\t2. Map sections into target process\n\t3. Inject loader shellcode\n\t4. Fix relocations\n\t5. Fix imports\n\t6. Call TLS callbacks\n\t7. Call DLLMain\n");
}
