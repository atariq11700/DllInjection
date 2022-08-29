#pragma once

#include <iostream>
#include <windows.h>
#include <string.h>
#include <direct.h>
#include <TlHelp32.h>

typedef BYTE* BYTEARRAY;

std::string getCwd();
std::string getLastErrorAsString();
BYTEARRAY isValidDll(std::string dllpath);
PROCESSENTRY32 getProcessEntryInfo(const char* szProcName = "");
void startProcess(std::string path, LPSTR lpCommandLine);