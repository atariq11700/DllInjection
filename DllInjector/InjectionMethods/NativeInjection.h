// 1. Alloc memory for the dll path using VirtualAllocEx
// 2. Write the dll path using WriteProcessMemory
// 3. Load the dll using CreateRemoteThreadEx


#pragma once
#include <iostream>
#include <Windows.h>
#include <string.h>

#include "injector.h"


class NativeInjection : public injectionmethod {
public:
    bool inject(DWORD dwTargetPid, std::string dllpath) override;
    void printDescription() override;
};