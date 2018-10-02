#include <ntifs.h>
#include "TypeOverwriteMitigation.h"
#include "PoolSliderMitigation.h"

extern "C" {
    DRIVER_INITIALIZE DriverEntry;
}

static
VOID
CreateProcessNotifyEx(
    _Inout_   PEPROCESS Process,
    _In_      HANDLE ProcessId,
    _In_opt_  PPS_CREATE_NOTIFY_INFO pCreateInfo
)
{
#ifdef _AMD64_
    if (pCreateInfo == nullptr) {
        // The process is being terminated.
        return;
    }

    NTSTATUS status = MitigateObjectTypeOverwrite(ProcessId, Process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to harden process %u against object type overwrite attack\n", HandleToULong(ProcessId));
    }
#else // _X86_
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(pCreateInfo);
#endif // _AMD64_

}

static
VOID
LoadImageNotify(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    PoolSliderLoadImageNotify(FullImageName, ProcessId, ImageInfo);
}

VOID
Unload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, TRUE);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);

    if (MmIsDriverVerifying(DriverObject)) {
        DbgPrint("*** WARNING: SKREAM might be incompatible with driver verifier! ***\n");
    }

    DriverObject->DriverUnload = Unload;

    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to register process creation notify routine, status = %08x\n", status);
        goto Exit;
    }

    status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to register load image notify routine, status = %08x\n", status);
        goto Exit;
    }

Exit:
    return status;
}
