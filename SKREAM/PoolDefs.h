#pragma once

#ifdef _AMD64_
#define POOL_GRANULARITY    (0x10)
#else // _X86_
#define POOL_GRANULARITY    (0x8)
#endif

//
// Evaluates to 0xfffffff8 on 32-bits and to 0xfffffffffffffff0 on 64-bits.
//

#define POOL_ALIGNMENT_MASK (MAXULONG_PTR - POOL_GRANULARITY + 1)

#define DEFAULT_ALLOCATION_TAG  ('enoN')
#define DEFAULT_FREE_TAG        (0)

#pragma warning(disable : 4201)

// POOL_HEADER struct taken from reactOs
typedef struct _POOL_HEADER
{
    union
    {
        struct
        {
            USHORT PreviousSize : 8;
            USHORT PoolIndex : 8;
            USHORT BlockSize : 8;
            USHORT PoolType : 8;
        };
        ULONG Ulong1;
    };
#ifdef _M_AMD64
    ULONG PoolTag;
#endif
    union
    {
#ifdef _M_AMD64
        PEPROCESS ProcessBilled;
#else
        ULONG PoolTag;
#endif
        struct
        {
            USHORT AllocatorBackTraceIndex;
            USHORT PoolTagHash;
        };
    };
} POOL_HEADER, *PPOOL_HEADER;

#pragma warning(default : 4201)