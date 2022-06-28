#include "utils.h"
#include "log.h"

#include <TlHelp32.h>


std::string getCwd() {
    char buff[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, (LPSTR)&buff);
    std::string res(buff);
    return res; 
}

std::string getLastErrorAsString() {
    DWORD error = GetLastError();
    if (error == 0) {
        return std::string();
    }

    LPSTR message_buffer;
    DWORD message_size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&message_buffer,
        0,
        NULL
    );

    std::string message(message_buffer, message_size);
    LocalFree(message_buffer);

    return message;
}

BYTEARRAY isValidDll(std::string dllpath) {
    const char* szDllPath = dllpath.c_str();

    printfInfo("Checking the validity of %s\n", szDllPath);

    //check that the dll file exists
    if (!GetFileAttributesA(szDllPath)) {
        printfError("Dll file %s doesn't exist\n", szDllPath);
        return nullptr;
    }

    //open the dll and check the size
    FILE* dllfile;
    fopen_s(&dllfile, szDllPath, "rb");

    if (!dllfile) {
        printfError("Failed to open the dll file\n");
        fclose(dllfile);
        return nullptr;
    } else {
        printfInfo("Opened the dll file\n");
    }

    fseek(dllfile, 0, SEEK_END);
    int filesize = ftell(dllfile);
    fseek(dllfile, 0, SEEK_SET);

    if (filesize < 0x1000) {
        printfError("Dll has invalid filesize\n");
        fclose(dllfile);
        return nullptr;
    } else {
        printfInfo("Dll has a valid size\n");
    }

    //read the dll file into a byte buffer
    BYTE* pDllBinaryData = new BYTE[filesize];
    if (!pDllBinaryData) {
        printfError("Failed to allocate space for dll\n");
        fclose(dllfile);
        delete[] pDllBinaryData;
        return nullptr;
    } else {
        printfInfo("Allocated %d bytes for the dll\n", filesize);
    }
    
    if (fread(pDllBinaryData, filesize, 1, dllfile) != 1) {
        printfError("Failed to read the dll \n");
        fclose(dllfile);
        delete[] pDllBinaryData;
        return nullptr;
    } else {
        printfInfo("Read the dll file\n");
        fclose(dllfile);
    }

    //check for MZ bytes
    if (((IMAGE_DOS_HEADER*)pDllBinaryData)->e_magic != IMAGE_DOS_SIGNATURE) {
        printfError("Dll file is not a valid pe image\n");
        delete[] pDllBinaryData;
    }  

    IMAGE_NT_HEADERS*       pDllNtHeader    =   (IMAGE_NT_HEADERS*)(pDllBinaryData + ((IMAGE_DOS_HEADER*)pDllBinaryData)->e_lfanew);
    IMAGE_OPTIONAL_HEADER*  pDllOptHeader   =   (IMAGE_OPTIONAL_HEADER*)&pDllNtHeader->OptionalHeader;
    IMAGE_FILE_HEADER*      pDllFileHeader  =   (IMAGE_FILE_HEADER*)&pDllNtHeader->FileHeader;


#if _WIN64 == 1
    if (pDllFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
        printfError("Injector is running as 64bit and the dll is not 64bit\n");
        delete[] pDllBinaryData;
        return nullptr;
    }
#elif _WIN32 == 1
    if (pDllFileHeader->Machine != IMAGE_FILE_MACHINE_I386) {
        printfError("Injector is running as 32bit and the dll is not 32bit\n");
        delete[] pDllBinaryData;
        return nullptr;
    }
#else
    printfError("Injector compiled for an unknown architecture. Please make sure to compile for either x86 or x64 and define the respective _WIN64 or _WIN32 macro\n");
    delete[] pDllBinaryData;
    return nullptr;
#endif

    printfSucc("Dll is valid\n");
    return pDllBinaryData;

}


DWORD getProcessPid(const char* szProcName) {
    DWORD dwPid = 0;

    PROCESSENTRY32 pe32Entry;
    pe32Entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (!Process32First(hProcSnapshot, &pe32Entry)) {
        printfError("Process32First Failed\n");
        exit(1);
    }

    do {
        if (_stricmp(szProcName, pe32Entry.szExeFile) == 0) {
            dwPid = pe32Entry.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcSnapshot, &pe32Entry));
    CloseHandle(hProcSnapshot);

    return dwPid;
}