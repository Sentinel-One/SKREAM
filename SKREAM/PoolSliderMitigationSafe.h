#pragma once

#include <ntifs.h>

VOID
PoolSliderLoadImageNotifySafeMitigation(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);
