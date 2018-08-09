#pragma once

#include <wdm.h>

NTSTATUS
MitigateObjectTypeOverwrite(
    _In_ HANDLE processId,
    _In_ PEPROCESS processObject
);