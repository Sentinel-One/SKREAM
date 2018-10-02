#include "Random.h"

auto RNG::get() -> RNG&
{
    static RNG instance;
    return instance;
}

ULONG RNG::rand()
{
    return RtlRandomEx(&m_Seed);
}

ULONG RNG::rand(_In_ ULONG max)
{
    return rand() % max;
}

ULONG RNG::rand(_In_ ULONG min, _In_ ULONG max)
{
    return rand() % (max + 1 - min) + min;
}

RNG::RNG()
{
     LARGE_INTEGER Counter = KeQueryPerformanceCounter(nullptr);
     m_Seed = Counter.LowPart ^ Counter.HighPart;
}
