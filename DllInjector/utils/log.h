#pragma once

#include <iostream>
#include <windows.h>


static HANDLE STD_OUT = GetStdHandle(STD_OUTPUT_HANDLE);

template<typename... argsTypes>
void printfError(const char* format, argsTypes... args) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(STD_OUT, &csbi);
    SetConsoleTextAttribute(STD_OUT, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("%-12s", "[Error]");
    SetConsoleTextAttribute(STD_OUT, csbi.wAttributes);
    printf(format, args...);
}


template<typename... argsTypes>
void printfInfo(const char* format, argsTypes... args) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(STD_OUT, &csbi);
    SetConsoleTextAttribute(STD_OUT, FOREGROUND_BLUE);
    printf("%-12s", "[Info]");
    SetConsoleTextAttribute(STD_OUT, csbi.wAttributes);
    printf(format, args...);
}


template<typename... argsTypes>
void printfSucc(const char* format, argsTypes... args) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(STD_OUT, &csbi);
    SetConsoleTextAttribute(STD_OUT, FOREGROUND_GREEN);
    printf("%-12s", "[Success]");
    SetConsoleTextAttribute(STD_OUT, csbi.wAttributes);
    printf(format, args...);
}