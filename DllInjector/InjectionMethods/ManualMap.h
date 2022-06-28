#pragma once

#include "injector.h"


class ManualMap : public injectionmethod {
public:
    bool inject(DWORD dwTargetPid, std::string dllpath) override;
    void printDescription() override;
};