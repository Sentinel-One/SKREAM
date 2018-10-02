#include "PoolSliderMitigation.h"
#include <ntifs.h>
#include "DetoursKernel.h"

PVOID
NTAPI
ExAllocatePoolWithTag_Hook(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
)
{
    return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
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

    if (pvFunc && pszName && strcmp(pszName, "ExAllocatePoolWithTag") == 0) {
        // Instruct Detours to stop enumeration.
        result = FALSE;

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

            *reinterpret_cast<ULONG_PTR *>(pWritableImportEntry) = reinterpret_cast<ULONG_PTR>(ExAllocatePoolWithTag_Hook);

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