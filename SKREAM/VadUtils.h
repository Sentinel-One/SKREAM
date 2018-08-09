#pragma once

#include "NativeStructs7.h"
#include "NativeStructs8.h"

NTSTATUS BBFindVAD(_In_ PEPROCESS pProcess, _In_ ULONG_PTR address, _Out_ win7::PMMVAD_SHORT * pResult);
NTSTATUS BBFindVAD(_In_ PEPROCESS pProcess, _In_ ULONG_PTR address, _Out_ win8::PMMVAD_SHORT * pResult);

NTSTATUS SecureVAD(_Out_ win7::PMMVAD_LONG pLongVad);
NTSTATUS SecureVAD(_Out_ win8::PMMVAD pVad);