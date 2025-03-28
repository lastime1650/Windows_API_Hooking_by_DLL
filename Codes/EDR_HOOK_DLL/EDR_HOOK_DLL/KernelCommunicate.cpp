
#include "pch.h"
#include <Windows.h>
#include <stdio.h>

#include "Kernel_Communicate_.h"


HANDLE KERNEL_DEVICE_HANDLE = 0;

// 1. IOCTL �ڵ� ȹ��
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
            printf("����̹� �ڵ� ȹ�� ����! ���� �ڵ�: %d\n", error);
            KERNEL_DEVICE_HANDLE = NULL;
            return FALSE;
        }
	}
    return TRUE;
}

typedef struct IOCTL_STRUCT {
    CHAR API_NAME[50];
    HANDLE PID;
    PUCHAR BUFFER; // [����] �����ּ� 
    ULONG32 BUFFER_SIZE; 
}IOCTL_STRUCT, *PIOCTL_STRUCT;

// 2. IOCTL ����
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
        &data,  // �Է� ���� ����
        sizeof(IOCTL_STRUCT),     // �Է� ���� ũ�� 0
        NULL,  // ��� ���� ����
        0,     // ��� ���� ũ�� 0
        &bytesReturned,
        NULL);
    if (!result) {
        DWORD error = GetLastError();
        printf("IOCTL ���� ����! ���� �ڵ�: %d\n", error);
        return FALSE;
    }

    printf("IOCTL ���� ����! ��ȯ�� ����Ʈ ��: %d\n", bytesReturned);

    return TRUE;
}
