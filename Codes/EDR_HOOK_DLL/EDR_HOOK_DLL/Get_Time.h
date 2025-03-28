#ifndef GET_TIME

#include <Windows.h>

#define output_time_buffer_size 24

PCHAR GetTimeStamp();

ULONG32 Get_TimeStamp_BuffLen();

VOID FREE_GetTimeStamp(PCHAR time_data);

#endif