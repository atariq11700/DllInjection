#pragma once

#include <iostream>
#include <windows.h>
#include <string.h>



class injectionmethod {
public:
    virtual bool inject(DWORD dwTargetPid, std::string dllpath) = 0;
    virtual void printDescription() = 0;
};