#include "pch.h"
#include "NTSTATUS_2_STRING.h"

#include <stdio.h>
#include <stdlib.h>


PCHAR NTSTATUS_2_STRING(NTSTATUS input, ULONG32* output_strlen) {

    PCHAR errorMessage = (PCHAR)malloc(NTSTATUS_2_STRING_alloc_size);

    DWORD dosError = RtlNtStatusToDosError(input);

    if (FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dosError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 시스템 기본 언어 사용
        errorMessage,
        NTSTATUS_2_STRING_alloc_size / sizeof(CHAR),
        NULL) == 0) {
        // FormatMessage 실패 시 일반적인 오류 메시지 반환
        sprintf_s(errorMessage, NTSTATUS_2_STRING_alloc_size, "Unknown NTSTATUS: 0x%08X", input);
    }

    if (output_strlen)
        *output_strlen = strlen(errorMessage);

    return errorMessage;
}

VOID FREE_NTSTATUS_2_STRING(PCHAR input) {
	free(input);
}