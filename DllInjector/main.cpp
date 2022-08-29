#include <iostream>
#include <windows.h>

#include <TlHelp32.h>
#include <vector>
#include <string>
#include <direct.h>
#include <time.h>

#include "utils/utils.h"
#include "utils/log.h"

#include "InjectionMethods/injector.h"
#include "InjectionMethods/NativeInjection.h"
#include "InjectionMethods/ManualMap.h"

#define vsbuild 1
#define x64bdg 0


#if vsbuild == 1
#if _WIN64 == 1
    #if NDEBUG == 1
        std::string reletiveDir = "\\x64\\Release\\";
    #elif _DEBUG == 1
        std::string reletiveDir = "\\x64\\Debug\\";
    #endif
#elif _WIN32 == 1
    #if NDEBUG == 1
        std::string reletiveDir = "\\Win32\\Release\\";
    #elif _DEBUG == 1
        std::string reletiveDir = "\\Win32\\Debug\\";
    #endif
#endif
#else
    #if x64bdg == 1
        std::string reletiveDir = "\\";
    #endif
#endif

    std::string TARGET_PROCESS_NAME = "dummyprocess.exe";
    //std::string TARGET_PROCESS_NAME = "notepad.exe";
    std::string DLL_NAME =  "dlltobeinjected.dll";



int main(int argc, const char** argv, const char** envp) {

    PROCESSENTRY32 peInfo;
    int counter = 0;

    do {
        //dwPid = getProcessPid(TARGET_PROCESS_NAME.c_str());
        peInfo  = getProcessEntryInfo();
        printfInfo("Target Process: [%d] %s\n", peInfo.th32ProcessID, peInfo.szExeFile);


        if (!peInfo.th32ProcessID) {
            printfError("PID 0 not valid\n");
            //printfInfo("Starting process\n");
            //startProcess(getCwd() + reletiveDir + TARGET_PROCESS_NAME, (LPSTR)argv[1]);
        }
        else {
            printfSucc("Found target process pid: %d\n", peInfo.th32ProcessID);
        }

        counter++;

        if (counter > 4) {
            printfError("Unable to start the target process after %d tries\n", counter);
            exit(1);
        }

    } while (!peInfo.th32ProcessID);

    

    std::vector<injectionmethod*> methods = {new NativeInjection(), new ManualMap()};


    for (int i = 1; i < methods.size() + 1; i++) {
        printf("(%d)  ", i);
        methods.at(i-1)->printDescription();
    }

    printf("Choose a method:>");
    std::string input;
    std::cin >> input;
    std::cin.ignore();

    int methodChoice = std::stoi(input);

    if (methods.at(methodChoice - 1)->inject(peInfo.th32ProcessID, getCwd() + reletiveDir + DLL_NAME)) {
        printfSucc("Injection succeded\n");
        std::cin.get();
        return 0;
    } else {
        printfError("Injection failed\n");
        std::cin.get();
        return 1;
    }

    
}