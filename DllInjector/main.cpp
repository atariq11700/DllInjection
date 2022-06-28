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
#include "InjectionMethods/Reflective.h"

    const char* TARGET_PROCESS_NAME = "dummyprocess.exe";

    //relative path to cwd
    const char* DLL_PATH =  "\\..\\x64\\Release\\dlltobeinjected.dll";

int main(int argc, const char** argv, const char** envp) {

    DWORD dwPid;
    int counter = 0;

    do {
        dwPid = getProcessPid(TARGET_PROCESS_NAME);

        if (!dwPid) {
            printfError("Unable to find the target process\n");
            printfInfo("Starting process\n");
            startProcess(getCwd() + "\\..\\x64\\Release\\" + TARGET_PROCESS_NAME, (LPSTR)argv[1]);
        }
        else {
            printfSucc("Found target process pid: %d\n", dwPid);
        }

        counter++;

        if (counter > 5) {
            printfError("Unable to start the target process after %d tries\n", counter);
            exit(1);
        }

    } while (!dwPid);

    

    std::vector<injectionmethod*> methods = {new NativeInjection(), new ManualMap(), new Reflective()};


    for (int i = 1; i < methods.size() + 1; i++) {
        printf("(%d)  ", i);
        methods.at(i-1)->printDescription();
    }

    printf("Choose a method:>");
    std::string input;
    std::cin >> input;
    std::cin.ignore();

    int methodChoice = std::stoi(input);

    if (methods.at(methodChoice - 1)->inject(dwPid, getCwd() + DLL_PATH)) {
        printfSucc("Injection succeded\n");
        std::cin.get();
        return 0;
    } else {
        printfError("Injection failed\n");
        std::cin.get();
        return 1;
    }

    
}