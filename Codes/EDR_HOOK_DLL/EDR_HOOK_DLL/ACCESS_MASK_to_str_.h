#ifndef ACCESSMASK_TO_STRING

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

PCHAR AccessMaskToString(DWORD accessMask, ULONG32* opt_output_strlen);
VOID FREE_AccessMaskToString(PCHAR Str);

#endif