#include "PoolSliderMitigation.h"
#include <ntifs.h>
#include "DetoursKernel.h"
#include "NativeStructs81.h"
#include "Random.h"
#include <fltKernel.h>

static
ULONG
GetPoolBlockSize(_In_ PVOID pBlock)
{
    static_assert(sizeof(win81::POOL_HEADER) == 16, "Bad pool header format");

    auto pPoolHeader = reinterpret_cast<win81::PPOOL_HEADER>(
        reinterpret_cast<ULONG_PTR>(pBlock) - sizeof(win81::POOL_HEADER));
    return pPoolHeader->BlockSize * sizeof(win81::POOL_HEADER);
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
    
    auto BlockSizeInBytes = GetPoolBlockSize(p);

    //
    // Calculate the amount of padding we have.
    //

    auto Padding = BlockSizeInBytes - sizeof(win81::POOL_HEADER) - NumberOfBytes;
    if ((Padding == 0) || (Padding > 16)) {
        __debugbreak();
        goto Exit;
    }

    //
    // Add a random delta to the allocation.
    //

    auto delta = RNG::get().rand(1, Padding % 16);
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
    // Align back to 16-byte granularity.
    //

    P = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(P) & 0xfffffffffffffff0);
    ExFreePoolWithTag(P, Tag);
}

BOOLEAN
NTAPI
ImportFuncCallbackEx(
    _In_opt_ PVOID pContext,
    _In_     ULONG nOrdinal,
    _In_opt_ PCSTR pszName,
    _In_opt_ PVOID *pvFunc)
{
    UNREFERENCED_PARAMETER(pContext);
    UNREFERENCED_PARAMETER(nOrdinal);

    BOOLEAN result = TRUE; // Instruct Detours to continue enumeration.

    if (pvFunc && pszName &&
        ((strcmp(pszName, "ExAllocatePoolWithTag") == 0) || (strcmp(pszName, "ExFreePoolWithTag") == 0))) {
        // Instruct Detours to stop enumeration.
        //result = FALSE;

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

            if (strcmp(pszName, "ExAllocatePoolWithTag") == 0) {
                *reinterpret_cast<ULONG_PTR *>(pWritableImportEntry) = reinterpret_cast<ULONG_PTR>(ExAllocatePoolWithTag_Hook);
            }
            else if (strcmp(pszName, "ExFreePoolWithTag") == 0) {
                *reinterpret_cast<ULONG_PTR *>(pWritableImportEntry) = reinterpret_cast<ULONG_PTR>(ExFreePoolWithTag_Hook);
            }
            else {
                NT_ASSERT(FALSE);
            }

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

    return result;
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
    // Hook ExAllocatePoolWithTag.
    //

    DetourEnumerateImportsEx(ImageInfo->ImageBase, nullptr, nullptr, ImportFuncCallbackEx);
}