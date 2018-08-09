#include <ntifs.h>
#include <ntdef.h>
#include <minwindef.h>
#include "NativeStructs7.h"
#include "NativeStructs8.h"
#include "VadUtils.h"

enum PROCESS_ACCESS_MASK : ACCESS_MASK {
    PROCESS_TERMINATE = 0x0001,
    PROCESS_CREATE_THREAD = 0x0002,
    PROCESS_VM_OPERATION = 0x0008,
    PROCESS_VM_WRITE = 0x0020,
    PROCESS_CREATE_PROCESS = 0x0080,
    PROCESS_SET_QUOTA = 0x0100,
    PROCESS_SET_INFORMATION = 0x0200,
    PROCESS_SUSPEND_RESUME = 0x0800,
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
    PROCESS_SET_LIMITED_INFORMATION = 0x2000,
    PROCESS_QUERY_INFORMATION = 0x0400,
};

enum VAD_POOL_TAGS : ULONG {
    LONG_VAD_POOL_TAG = 'ldaV',
    SHORT_VAD_POOL_TAG = 'SdaV',
};

/**
* kd> dps nt!ObTypeIndexTable
* fffff800`02c75d40  00000000`00000000
* fffff800`02c75d48  00000000`bad0b0b0
* fffff800`02c75d50  fffffa80`01848b30
* fffff800`02c75d58  fffffa80`018489e0
* fffff800`02c75d60  fffffa80`018e5080
* fffff800`02c75d68  fffffa80`018e5e50
* fffff800`02c75d70  fffffa80`018e5c30
* fffff800`02c75d78  fffffa80`018e5ae0
* fffff800`02c75d80  fffffa80`018e5990
* fffff800`02c75d88  fffffa80`018e5840
* fffff800`02c75d90  fffffa80`018e56f0
* fffff800`02c75d98  fffffa80`018e54b0
* fffff800`02c75da0  fffffa80`01966270
* fffff800`02c75da8  fffffa80`018e8210
* fffff800`02c75db0  fffffa80`0197b5c0
* fffff800`02c75db8  fffffa80`01982620
*/

static constexpr ULONG MM_ALLOCATION_GRANULARITY = 64 * 1024;
static constexpr ULONG_PTR OBJECT_TYPE_BAD0B0B0 = 0x00000000bad0b0b0;

EXTERN_C PVOID PsGetProcessWow64Process(_In_ PEPROCESS);

static
NTSTATUS
MitigateObjectTypeOverwriteWin8(
    _In_ PEPROCESS processObject
)
{
    NTSTATUS status = STATUS_SUCCESS;

    //
    // Find the VAD node in the tree representing the preceding allocation.
    //

    win8::PMMVAD_SHORT shortVad = nullptr;
    status = BBFindVAD(processObject, OBJECT_TYPE_BAD0B0B0, &shortVad);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to find VAD, status = %08x\n", status);
        return status;
    }

    //
    // Allocate a longer VAD.
    //

    win8::PMMVAD longerVad = nullptr;
    longerVad = static_cast<win8::PMMVAD>(ExAllocatePoolWithTag(NonPagedPool, sizeof(win8::MMVAD), LONG_VAD_POOL_TAG));

    if (!longerVad) {
        DbgPrint("Failed to allocate longer VAD, insufficient resources\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }

    RtlZeroMemory(longerVad, sizeof(*longerVad));

    //
    // Copy the short VAD into the long VAD.
    //

    longerVad->Core = *shortVad;

    //
    // Secure the VAD against malicious attempts to free, unprotect or modify it in any way.
    // There is no need to explicitly set 'MemCommit', 'PrivateMemory' and 'Protection' as they already had their
    // correct values when the short VAD was allocated.
    //
    // longerVad->Core.u1.VadFlags1.MemCommit = FALSE;
    // longerVad->Core.u.VadFlags.PrivateMemory = TRUE;
    // longerVad->Core.u.VadFlags.Protection = MM_NOACCESS;
    //

    status = SecureVAD(longerVad);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to secure VAD, status = %08x\n", status);
        return status;
    }

    //
    // Setup child nodes.
    //

    if (longerVad->Core.VadNode.LeftChild) {

        //
        // Our node has a left child, make its parent the new, long VAD.
        //

        longerVad->Core.VadNode.LeftChild->u1.Parent = reinterpret_cast<win8::PMMADDRESS_NODE>(longerVad);
    }

    if (longerVad->Core.VadNode.RightChild) {

        //
        // Our node has a right child, make its parent the new, long VAD.
        //

        longerVad->Core.VadNode.RightChild->u1.Parent = reinterpret_cast<win8::PMMADDRESS_NODE>(longerVad);
    }

    //
    // Link the new node back to the VAD tree.
    //

    PVOID oldShortVad = nullptr;

    if (shortVad->VadNode.u1.Parent->LeftChild == reinterpret_cast<win8::PMMADDRESS_NODE>(shortVad)) {

        //
        // The short VAD is the left child of the parent node, so replace it with the corresponding long VAD.
        //

        oldShortVad = InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID *>(&shortVad->VadNode.u1.Parent->LeftChild),
            reinterpret_cast<win8::PMMADDRESS_NODE>(longerVad));
    }
    else if (shortVad->VadNode.u1.Parent->RightChild == reinterpret_cast<win8::PMMADDRESS_NODE>(shortVad)) {
        
        //
        // The short VAD is the right child of the parent node, so replace it with the corresponding long VAD.
        //

        oldShortVad = InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID *>(&shortVad->VadNode.u1.Parent->RightChild),
            reinterpret_cast<win8::PMMADDRESS_NODE>(longerVad));
    }
    else {

        //
        // Anomaly!
        //

        DbgPrint("Couldn't link the long VAD back to the VAD tree.\n");
        NT_ASSERT(FALSE);
    }

    //
    // Free the old VAD entry.
    //

    NT_ASSERT(oldShortVad == shortVad);
    ExFreePoolWithTag(oldShortVad, SHORT_VAD_POOL_TAG);

    return status;
}

static
NTSTATUS
MitigateObjectTypeOverwriteWin7(
    _In_ PEPROCESS processObject
)
{
    NTSTATUS status = STATUS_SUCCESS;

    //
    // Find the VAD node in the tree representing the preceding allocation.
    //

    win7::PMMVAD_SHORT shortVad = nullptr;
    status = BBFindVAD(processObject, OBJECT_TYPE_BAD0B0B0, &shortVad);
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to find VAD, status = %08x\n", status);
        return status;
    }

    //
    // Allocate a long VAD.
    //

    win7::PMMVAD_LONG longVad = nullptr;
    longVad = reinterpret_cast<decltype(longVad)>(ExAllocatePoolWithTag(NonPagedPool, sizeof(*longVad), LONG_VAD_POOL_TAG));

    if (!longVad) {
        DbgPrint("Failed to allocate long VAD, insufficient resources\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        return status;
    }

    RtlZeroMemory(longVad, sizeof(*longVad));

    //
    // Copy the short VAD into the long VAD.
    //

    longVad->vad.vadShort = *shortVad;

    //
    // Secure the VAD against malicious attempts to free, unprotect or modify it in any way.
    // There is no need to explicitly set 'MemCommit', 'PrivateMemory' and 'Protection' as they already had their
    // correct values when the short VAD was allocated.
    //
    // longVad->vad.vadShort.u.VadFlags.MemCommit = FALSE;
    // longVad->vad.vadShort.u.VadFlags.PrivateMemory = TRUE;
    // longVad->vad.vadShort.u.VadFlags.Protection = MM_NOACCESS;
    //

    status = SecureVAD(longVad);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to secure VAD, status = %08x\n", status);
        return status;
    }

    //
    // Setup child nodes.
    //

    if (longVad->vad.vadShort.LeftChild) {

        //
        // Our node has a left child, make its parent the new, long VAD.
        //

        longVad->vad.vadShort.LeftChild->vadShort.u1.Parent = reinterpret_cast<win7::PMMADDRESS_NODE>(longVad);
    }

    if (longVad->vad.vadShort.RightChild) {

        //
        // Our node has a right child, make its parent the new, long VAD.
        //

        longVad->vad.vadShort.RightChild->vadShort.u1.Parent = reinterpret_cast<win7::PMMADDRESS_NODE>(longVad);
    }

    //
    // Link the new node back to the VAD tree.
    //

    PVOID oldShortVad = nullptr;

    if (shortVad->u1.Parent->LeftChild == reinterpret_cast<win7::PMMADDRESS_NODE>(shortVad)) {

        //
        // The short VAD is the left child of the parent node, so replace it with the corresponding long VAD.
        //

        oldShortVad = InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID *>(&shortVad->u1.Parent->LeftChild),
            reinterpret_cast<win7::PMMADDRESS_NODE>(longVad));
    }
    else if (shortVad->u1.Parent->RightChild == reinterpret_cast<win7::PMMADDRESS_NODE>(shortVad)) {

        //
        // The short VAD is the right child of the parent node, so replace it with the corresponding long VAD.
        //

        oldShortVad = InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID *>(&shortVad->u1.Parent->RightChild),
            reinterpret_cast<win7::PMMADDRESS_NODE>(longVad));
    }
    else {

        //
        // Anomaly!
        //

        DbgPrint("Couldn't link the long VAD back to the VAD tree.\n");
        NT_ASSERT(FALSE);
    }

    //
    // Free the old VAD entry.
    //

    NT_ASSERT(oldShortVad == shortVad);
    ExFreePoolWithTag(oldShortVad, SHORT_VAD_POOL_TAG);

    return status;
}

NTSTATUS
MitigateObjectTypeOverwrite(
    _In_ HANDLE processId,
    _In_ PEPROCESS processObject
)
{
    NTSTATUS status = STATUS_SUCCESS;

    //
    // Check OS version.
    //

    if (RtlIsNtDdiVersionAvailable(NTDDI_WINBLUE) || !RtlIsNtDdiVersionAvailable(NTDDI_WIN7)) {
        DbgPrint("Unsuitable Windows version: this mitigation is only relevant for Windows 7 and 8.\n");
        return STATUS_SUCCESS;
    }

    //
    // Open the target process.
    //

    OBJECT_ATTRIBUTES procAttrs{};
    InitializeObjectAttributes(&procAttrs, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    CLIENT_ID cid{};
    cid.UniqueProcess = processId;
    
    HANDLE hProcess = nullptr;

    status = ZwOpenProcess(&hProcess, PROCESS_VM_OPERATION, &procAttrs, &cid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to open process with PID %u, status = %08x\n", HandleToULong(cid.UniqueProcess), status);
        return status;
    }

    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 0;

    __try {

        //
        // Allocate the 0xbad0b0b0 region.
        //

        baseAddress = ALIGN_DOWN_POINTER_BY(OBJECT_TYPE_BAD0B0B0, MM_ALLOCATION_GRANULARITY);
        regionSize = MM_ALLOCATION_GRANULARITY;
        
        status = ZwAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, MEM_RESERVE, PAGE_NOACCESS);
        if (!NT_SUCCESS(status)) {
            if (!PsGetProcessWow64Process(processObject)) {

                //
                // For WoW64 processes this failure is for the most time expected as normally all address space above
                // the 2GB boundary is reserved and can't be allocated.
                //

                DbgPrint("Failed to allocate 0xbad0b0b0 region, status = %08x\n", status);
            }

            baseAddress = nullptr;
            __leave;
        }

        //
        // Prevent the 0xbad0b0b0 region from being allocated, freed or unmapped.
        //

        bool isWindows7 = !RtlIsNtDdiVersionAvailable(NTDDI_WIN8);

        if (isWindows7) {
            status = MitigateObjectTypeOverwriteWin7(processObject);
        }
        else {
            status = MitigateObjectTypeOverwriteWin8(processObject);
        }
    }
    __finally {
        if (!NT_SUCCESS(status)) {

            //
            // Cleanup.
            //

            if (baseAddress) {
                regionSize = 0;
                ZwFreeVirtualMemory(hProcess, &baseAddress, &regionSize, MEM_RELEASE);
            }
        }

        if (hProcess) {
            ZwClose(hProcess);
        }
    }

    return status;
}
