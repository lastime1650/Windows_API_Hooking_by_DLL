
#include "pch.h"
#include <Windows.h>
#include <stdio.h>

#include "Kernel_Communicate_.h"


HANDLE KERNEL_DEVICE_HANDLE = 0;

// 1. IOCTL 핸들 획득
BOOLEAN Check_Kernel_Device() {
	if (!KERNEL_DEVICE_HANDLE) {
        KERNEL_DEVICE_HANDLE = CreateFileW(
            SYMLINK_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (KERNEL_DEVICE_HANDLE == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            printf("드라이버 핸들 획득 실패! 오류 코드: %d\n", error);
            KERNEL_DEVICE_HANDLE = NULL;
            return FALSE;
        }
	}
    return TRUE;
}

typedef struct IOCTL_STRUCT {
    CHAR API_NAME[50];
    HANDLE PID;
    PUCHAR BUFFER; // [주의] 가상주소 
    ULONG32 BUFFER_SIZE; 
}IOCTL_STRUCT, *PIOCTL_STRUCT;

// 2. IOCTL 전송
BOOLEAN Send_API_log(PCHAR API_NAME, PUCHAR Buffer, ULONG32 Buffer_Size) {

    if (!Check_Kernel_Device())
        return FALSE;

    IOCTL_STRUCT data = { 0 };
    memset(&data, 0, sizeof(IOCTL_STRUCT));
    data.PID = (HANDLE)GetCurrentProcessId();
    data.BUFFER = Buffer;
    data.BUFFER_SIZE = Buffer_Size;

    memcpy(data.API_NAME, API_NAME, strlen(API_NAME) + 1);



    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        KERNEL_DEVICE_HANDLE,
        IOCTL_by_API,
        &data,  // 입력 버퍼 없음
        sizeof(IOCTL_STRUCT),     // 입력 버퍼 크기 0
        NULL,  // 출력 버퍼 없음
        0,     // 출력 버퍼 크기 0
        &bytesReturned,
        NULL);
    if (!result) {
        DWORD error = GetLastError();
        printf("IOCTL 전송 실패! 오류 코드: %d\n", error);
        return FALSE;
    }

    printf("IOCTL 전송 성공! 반환된 바이트 수: %d\n", bytesReturned);

    return TRUE;
}
