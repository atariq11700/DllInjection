#pragma once

#include "injector.h"


class Reflective : public injectionmethod {
public:
    bool inject(DWORD dwTargetPid, std::string dllpath) override;
    void printDescription() override;
};