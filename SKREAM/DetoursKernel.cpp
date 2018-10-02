#include "DetoursKernel.h"
#include <ntimage.h>

static inline
PUCHAR
RvaAdjust(_Pre_notnull_ PIMAGE_DOS_HEADER pDosHeader, _In_ ULONG raddr)
{
    if (raddr != NULL) {
        return ((PUCHAR)pDosHeader) + raddr;
    }
    return NULL;
}

NTSTATUS
NTAPI
DetourEnumerateImportsEx(
    _In_opt_ PVOID hModule,
    _In_opt_ PVOID pContext,
    _In_opt_ PF_DETOUR_IMPORT_FILE_CALLBACK pfImportFile,
    _In_opt_ PF_DETOUR_IMPORT_FUNC_CALLBACK_EX pfImportFunc)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;

    __try {
#pragma warning(suppress:6011) // GetModuleHandleW(NULL) never returns NULL.
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return STATUS_INVALID_IMAGE_NOT_MZ;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader +
            pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_IMPORT_DESCRIPTOR iidp
            = (PIMAGE_IMPORT_DESCRIPTOR)
            RvaAdjust(pDosHeader,
                pNtHeader->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        if (iidp == NULL) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        for (; iidp->OriginalFirstThunk != 0; iidp++) {

            PCSTR pszName = (PCHAR)RvaAdjust(pDosHeader, iidp->Name);
            if (pszName == NULL) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            PIMAGE_THUNK_DATA pThunks = (PIMAGE_THUNK_DATA)
                RvaAdjust(pDosHeader, iidp->OriginalFirstThunk);
            PVOID * pAddrs = (PVOID *)
                RvaAdjust(pDosHeader, iidp->FirstThunk);

            //PVOID hFile = DetourGetContainingModule(pAddrs[0]);
            PVOID hFile = NULL;

            if (pfImportFile != NULL) {
                if (!pfImportFile(pContext, hFile, pszName)) {
                    break;
                }
            }

            ULONG nNames = 0;
            if (pThunks) {
                for (; pThunks[nNames].u1.Ordinal; nNames++) {
                    ULONG nOrdinal = 0;
                    PCSTR pszFunc = NULL;

                    if (IMAGE_SNAP_BY_ORDINAL(pThunks[nNames].u1.Ordinal)) {
                        nOrdinal = (ULONG)IMAGE_ORDINAL(pThunks[nNames].u1.Ordinal);
                    }
                    else {
                        pszFunc = (PCSTR)RvaAdjust(pDosHeader,
                            (ULONG)pThunks[nNames].u1.AddressOfData + 2);
                    }

                    if (pfImportFunc != NULL) {
                        if (!pfImportFunc(pContext,
                            nOrdinal,
                            pszFunc,
                            &pAddrs[nNames])) {
                            break;
                        }
                    }
                }
                if (pfImportFunc != NULL) {
                    pfImportFunc(pContext, 0, NULL, NULL);
                }
            }
        }
        if (pfImportFile != NULL) {
            pfImportFile(pContext, NULL, NULL);
        }
        return STATUS_SUCCESS;
    }
    __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION ?
        EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
}

