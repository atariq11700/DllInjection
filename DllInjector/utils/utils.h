#pragma once

#include <iostream>
#include <windows.h>
#include <string.h>
#include <direct.h>

typedef BYTE* BYTEARRAY;

std::string getCwd();
std::string getLastErrorAsString();
BYTEARRAY isValidDll(std::string dllpath);
DWORD getProcessPid(const char* szProcName);
void startProcess(std::string path, LPSTR lpCommandLine);