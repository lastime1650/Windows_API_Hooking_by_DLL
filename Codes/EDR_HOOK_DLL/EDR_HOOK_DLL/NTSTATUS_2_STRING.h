#ifndef NTSTATUS_2_STring_

#include <Windows.h>
#include <winternl.h>


#define NTSTATUS_2_STRING_alloc_size 256

PCHAR NTSTATUS_2_STRING(NTSTATUS input, ULONG32* output_strlen);

VOID FREE_NTSTATUS_2_STRING(PCHAR input);

#endif