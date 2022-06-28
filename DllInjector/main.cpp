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
    const char* DLL_PATH =  "\\DllSource\\bin\\dlltobeinjected.dll";

int main(int argc, const char** argv, const char** envp) {

    DWORD dwPid = getProcessPid(TARGET_PROCESS_NAME);

    if (!dwPid) {
        printfError("Unable to find the target process\n");
        printfInfo("Starting process\n");

        exit(1);
    } else {
        printfSucc("Found target process pid: %d\n", dwPid);
    }

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