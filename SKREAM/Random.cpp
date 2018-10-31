#include "Random.h"

auto RNG::get() -> RNG&
{
    static RNG instance;
    return instance;
}

ULONG RNG::rand()
{
    //
    // We are not using RtlRandom(Ex) since these functions can only operate at IRQL <= APC_LEVEL, and we want our rand()
    // implementation to work at DISPATCH_LEVEL as well.
    //

    m_Seed = m_Seed * 1103515245 + 12345;
    return static_cast<ULONG>((m_Seed / 65536) % 32768);
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

