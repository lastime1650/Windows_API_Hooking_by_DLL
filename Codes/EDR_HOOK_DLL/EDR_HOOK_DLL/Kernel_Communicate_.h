#ifndef KERNE_COMM
#define ENUMsdas
#include <Windows.h>
#include <winioctl.h>

#define SYMLINK_NAME L"\\??\\My_AGENT_Device"
#define IOCTL_by_API CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) // APIÀü¿ë CODE

BOOLEAN Check_Kernel_Device();
BOOLEAN Send_API_log(PCHAR API_NAME, PUCHAR Buffer, ULONG32 Buffer_Size);

#endif