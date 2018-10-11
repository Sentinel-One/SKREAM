#include "PoolSliderMitigation.h"
#include "DetoursKernel.h"
#include "Random.h"
#include <ntifs.h>
#include <fltKernel.h>

#ifdef _AMD64_
#define POOL_GRANULARITY 0x10
#else // X86
#define POOL_GRANULARITY 0x8
#endif

static
ULONG
GetPoolBlockSizeInBytes(_In_ PVOID pBlock)
{
    static_assert(sizeof(POOL_HEADER) == POOL_GRANULARITY, "bad pool header");
    auto pPoolHeader = reinterpret_cast<PPOOL_HEADER>(
        reinterpret_cast<ULONG_PTR>(pBlock) - sizeof(POOL_HEADER));
    return pPoolHeader->BlockSize * POOL_GRANULARITY;
}

PVOID
NTAPI
ExAllocatePoolWithTag_Hook(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
)
{
    //
    // Call original pool routine.
    //

    PVOID p = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);

    if (!p) {

        //
        // There is nothing we can do to failed allocations.
        //

        goto Exit;
    }

    if (NumberOfBytes > 0xff0) {

        //
        // Allocations bigger than a page size are handled separately.
        //

        goto Exit;
    }

    //
    // Retrieve the block size.
    //
    
    auto BlockSizeInBytes = GetPoolBlockSizeInBytes(p);

    //
    // Calculate the amount of padding we have.
    //

    ULONG Padding = BlockSizeInBytes - sizeof(POOL_HEADER) - static_cast<ULONG>(NumberOfBytes);
    if (Padding == 0) {
        goto Exit;
    }

    if (Padding > POOL_GRANULARITY - 1) {
        __debugbreak();
        //
        // This could happen when the specified pool type is CacheAligned.
        // In this case we'll only use the first 15 bytes of padding, 
        // so it'll be easier to align the address when the allocation is freed.
        //
        Padding = POOL_GRANULARITY - 1;
    }

    //
    // Add a random delta to the allocation.
    //

    auto delta = RNG::get().rand(1, Padding);
    p = Add2Ptr(p, delta);

Exit:
    return p;
}

VOID ExFreePoolWithTag_Hook(
    _In_ PVOID P,
    _In_ ULONG Tag
)
{
    //
    // Align back to normal pool granularity.
    //

    P = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(P) & (0xfffffffffffffff0 | POOL_GRANULARITY));
    ExFreePoolWithTag(P, Tag);
}

PVOID
NTAPI
ExAllocatePool_Hook(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes
)
{
    //
    // ExAllocatePool is a mere wrapper for ExAllocatePoolWithTag.
    //

    return ExAllocatePoolWithTag_Hook(PoolType, NumberOfBytes, 0);
}

VOID ExFreePool_Hook(
    _In_ PVOID P
)
{
    //
    // ExFreePool is a mere wrapper for ExFreePoolWithTag.
    //

    ExFreePoolWithTag_Hook(P, 0);
}

VOID RtlFreeAnsiString_Hook(
    _In_ PANSI_STRING AnsiString
)
{
    //
    // The documentation for RtlFreeAnsiString (see https://docs.microsoft.com/en-us/windows/desktop/api/winternl/nf-winternl-rtlfreeansistring)
    // clearly states that the purpose of this function is to "Free the string buffer allocated by RtlUnicodeStringToAnsiString."
    //
    // Unfortunately, some misbehaving drivers use this DDI to free a string buffer which was allocated directly by a
    // previous call to ExAllocatePool(WithTag). To overcome this discrepancy we chose to hook RtlFreeAnsiString and
    // align the string buffer ourselves if needed. Failure to do so will result in ExFreePool(WithTag) being called with
    // an unaligned pointer, thus leading to a inevitable BSOD.
    //

    auto P = reinterpret_cast<PVOID>(AnsiString->Buffer);
    P = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(P) & (0xfffffffffffffff0 | POOL_GRANULARITY));
    AnsiString->Buffer = reinterpret_cast<PCHAR>(P);
    RtlFreeAnsiString(AnsiString);
}

BOOLEAN
NTAPI
ImportFuncCallbackEx(
    _In_opt_ PVOID pContext,
    _In_     ULONG nOrdinal,
    _In_opt_ PCSTR pszName,
    _In_opt_ PVOID *pvFunc)
{
    UNREFERENCED_PARAMETER(nOrdinal);

    if (pvFunc && pszName) {

        //
        // Check if we encountered a function we wish to hook.
        //

        ULONG_PTR hookFunc = NULL;

        if (strcmp(pszName, "ExAllocatePoolWithTag") == 0) {
            hookFunc = reinterpret_cast<ULONG_PTR>(ExAllocatePoolWithTag_Hook);
        }
        else if (strcmp(pszName, "ExFreePoolWithTag") == 0) {
            hookFunc = reinterpret_cast<ULONG_PTR>(ExFreePoolWithTag_Hook);
        }
        else if (strcmp(pszName, "ExAllocatePool") == 0) {
            hookFunc = reinterpret_cast<ULONG_PTR>(ExAllocatePool_Hook);
        }
        else if (strcmp(pszName, "ExFreePool") == 0) {
            hookFunc = reinterpret_cast<ULONG_PTR>(ExFreePool_Hook);
        }
        else if (strcmp(pszName, "RtlFreeAnsiString") == 0 || strcmp(pszName, "RtlFreeUnicodeString") == 0) {
            hookFunc = reinterpret_cast<ULONG_PTR>(RtlFreeAnsiString_Hook);
        }

        if (hookFunc) {
            auto pDriverName = reinterpret_cast<PUNICODE_STRING>(pContext);
            DbgPrint("Hooking function %s in driver %wZ\n", pszName, pDriverName);
        }
        else {
            goto Exit;
        }

        PMDL pImportEntryMdl = nullptr;
        BOOLEAN LockedPages = FALSE;

        __try {

            //
            // Patch the IAT entry.
            //
            
            pImportEntryMdl = IoAllocateMdl(pvFunc, sizeof(ULONG_PTR), FALSE, FALSE, nullptr);
            if (!pImportEntryMdl) {
                DbgPrint("Could not allocate an MDL for import patch, insufficient resources.");
                __leave;
            }

            //
            // Although the entry point is expected to be in system address space this could still throw,
            // for example an in-page error.
            //

            __try {
                MmProbeAndLockPages(pImportEntryMdl, KernelMode, IoWriteAccess);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("Exception while trying to probe and lock the import entry, status: 0x%08x", GetExceptionCode());
                __leave;
            }

            LockedPages = TRUE;

            PVOID pWritableImportEntry = MmGetSystemAddressForMdlSafe(pImportEntryMdl, NormalPagePriority | MdlMappingNoExecute);
            if (!pWritableImportEntry) {
                DbgPrint("Failed acquiring a system VA for MDL, insufficient resources\n");
                __leave;
            }

            NTSTATUS status = MmProtectMdlSystemAddress(pImportEntryMdl, PAGE_READWRITE);
            if (!NT_SUCCESS(status)) {
                DbgPrint("Failed protecting the MDL system address, status: 0x%08x", status);
                __leave;
            }

            *reinterpret_cast<ULONG_PTR *>(pWritableImportEntry) = hookFunc;

        }
        __finally {
            if (pImportEntryMdl) {
                if (LockedPages) {
                    MmUnlockPages(pImportEntryMdl);
                }

                IoFreeMdl(pImportEntryMdl);
            }
        }
    }

Exit:
    return TRUE;
}

VOID
PoolSliderLoadImageNotify(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);

    if (!ImageInfo->SystemModeImage) {

        //
        // We only care about kernel-mode drivers.
        //

        return;
    }

    //
    // Hook some pool related routines.
    //

    DetourEnumerateImportsEx(ImageInfo->ImageBase, FullImageName, nullptr, ImportFuncCallbackEx);
}