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

ULONG RNG::rand2(void) // RAND_MAX assumed to be 32767
{
    m_Seed = m_Seed * 1103515245 + 12345;
    return (ULONG)(m_Seed / 65536) % 32768;
}

ULONG RNG::rand(_In_ ULONG max)
{
    return rand2() % max;
}

ULONG RNG::rand(_In_ ULONG min, _In_ ULONG max)
{
    return rand2() % (max + 1 - min) + min;
}

RNG::RNG()
{
     LARGE_INTEGER Counter = KeQueryPerformanceCounter(nullptr);
     m_Seed = Counter.LowPart ^ Counter.HighPart;
}

