#include "PoolBloaterMitigation.h"
#include "DetoursKernel.h"
#include "Random.h"
#include <ntifs.h>
#include <fltKernel.h>
#include "Config.h"
#include "PoolDefs.h"

static
PVOID
NTAPI
ExAllocatePoolWithTag_Hook(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
)
{
    //
    // Currently we don't do anything to allocations bigger than a page size.
    //

    if (NumberOfBytes <= (PAGE_SIZE -   sizeof(POOL_HEADER) - (MAX_POOL_CHUNKS_TO_ADD * POOL_GRANULARITY))) {

        //
        // Add a random number of chunks to the pool allocation without changing its base address or breaking its alignment.
        //

        auto PoolChunksToAdd = RNG::get().rand(MIN_POOL_CHUNKS_TO_ADD, MAX_POOL_CHUNKS_TO_ADD);
        NumberOfBytes += (PoolChunksToAdd * POOL_GRANULARITY);
    }

    return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);

}

static
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

    return ExAllocatePoolWithTag_Hook(PoolType, NumberOfBytes, DEFAULT_ALLOCATION_TAG);
}

static
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

        ULONG_PTR hookFunc = 0;

        if (strcmp(pszName, "ExAllocatePoolWithTag") == 0) {
            hookFunc = reinterpret_cast<ULONG_PTR>(ExAllocatePoolWithTag_Hook);
        }
        else if (strcmp(pszName, "ExAllocatePool") == 0) {
            hookFunc = reinterpret_cast<ULONG_PTR>(ExAllocatePool_Hook);
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
            // Although the imported entry is expected to be in system address space this could still throw,
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
PoolBloaterLoadImageNotify(
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
    // Hook ExAllocatePool and ExAllocatePoolWithTag.
    //

    DetourEnumerateImportsEx(ImageInfo->ImageBase, FullImageName, nullptr, ImportFuncCallbackEx);
}