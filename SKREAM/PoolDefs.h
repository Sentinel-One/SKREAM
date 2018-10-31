#pragma once

//
// POOL_HEADER structure taken from ReactOS.
// This isn't the most up-to-date definition, but for our purposes it will do.
//

#pragma warning(disable : 4201)
typedef struct _POOL_HEADER
{
    union
    {
#ifdef _AMD64_
        struct
        {
            USHORT PreviousSize : 8;
            USHORT PoolIndex : 8;
            USHORT BlockSize : 8;
            USHORT PoolType : 8;
        };
#else // _X86_
        struct
        {
            USHORT PreviousSize : 9;
            USHORT PoolIndex : 7;
            USHORT BlockSize : 9;
            USHORT PoolType : 7;
        };
#endif // _AMD64_
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

#ifdef _AMD64_
#define POOL_GRANULARITY    (0x10)
#else // _X86_
#define POOL_GRANULARITY    (0x8)
#endif

static_assert(sizeof(POOL_HEADER) == POOL_GRANULARITY, "Bad POOL_HEADER definition");

//
// Evaluates to 0xfffffff8 on 32-bits and to 0xfffffffffffffff0 on 64-bits.
//

#define POOL_ALIGNMENT_MASK (MAXULONG_PTR - POOL_GRANULARITY + 1)

//
// Default pool tags used by ExAllocatePool and ExFreePool.
//

#define DEFAULT_ALLOCATION_TAG  ('enoN')
#define DEFAULT_FREE_TAG        (0)

//
// Pool allocations greater than 4080 bytes (requiring a page or more) are handled by nt!ExpAllocateBigPool.
// See https://media.blackhat.com/bh-dc-11/Mandt/BlackHat_DC_2011_Mandt_kernelpool-wp.pdf fore more details.
//

#define BIG_POOL_ALLOCATION_THRESHOLD   (4080)
