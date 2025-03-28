#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "Get_Time.h"


PCHAR GetTimeStamp() {
    // 정적 버퍼 사용
    PCHAR timeBuffer = (PCHAR)malloc(output_time_buffer_size);
    memset(timeBuffer, 0, output_time_buffer_size);

    SYSTEMTIME systemTime;

    GetLocalTime(&systemTime);

    // YYYY-MM-DD HH:MM:SS.mmm 형식으로 포맷. wprintf_s를 사용합니다.
    int result = sprintf_s(
        timeBuffer,
        output_time_buffer_size,
        "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        systemTime.wYear,
        systemTime.wMonth,
        systemTime.wDay,
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond,
        systemTime.wMilliseconds
    );

    if (result < 0) {
        // 오류 처리: 버퍼가 너무 작거나 다른 오류가 발생했습니다.
        return NULL;
    }

    return timeBuffer;
}

ULONG32 Get_TimeStamp_BuffLen() {
    return output_time_buffer_size;
}

VOID FREE_GetTimeStamp(PCHAR time_data) {
    free(time_data);
}