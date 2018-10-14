#pragma once

#include <ntifs.h>

typedef BOOLEAN (NTAPI *PF_DETOUR_IMPORT_FILE_CALLBACK)(
    _In_opt_ PVOID pContext,
    _In_opt_ PVOID hModule,
    _In_opt_ LPCSTR pszFile);

// Same as PF_DETOUR_IMPORT_FUNC_CALLBACK but extra indirection on last parameter.
typedef BOOLEAN (NTAPI *PF_DETOUR_IMPORT_FUNC_CALLBACK_EX)(
    _In_opt_ PVOID pContext,
    _In_ ULONG nOrdinal,
    _In_opt_ LPCSTR pszFunc,
    _In_opt_ PVOID* ppvFunc);

//
// Borrowed from the MS Detours library (https://github.com/Microsoft/Detours) and adapted to the kernel environment.
//

NTSTATUS
NTAPI
DetourEnumerateImportsEx(
    _In_opt_ PVOID hModule,
    _In_opt_ PVOID pContext,
    _In_opt_ PF_DETOUR_IMPORT_FILE_CALLBACK pfImportFile,
    _In_opt_ PF_DETOUR_IMPORT_FUNC_CALLBACK_EX pfImportFunc);