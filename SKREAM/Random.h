#pragma once

#include <ntifs.h>

class RNG
{
public:
    static RNG& get();

    ULONG rand();
    ULONG rand(_In_ ULONG max);
    ULONG rand(_In_ ULONG min, _In_ ULONG max);

private:
    RNG();
    ULONG m_Seed = 0;
};

