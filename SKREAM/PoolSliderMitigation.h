#pragma once

#include <ntifs.h>
#include <minwindef.h>

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

VOID
PoolSliderLoadImageNotify(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);
