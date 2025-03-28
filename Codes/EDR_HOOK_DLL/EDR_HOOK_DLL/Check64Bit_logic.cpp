#include "pch.h"
#include "Check64Bit.h"

BOOLEAN is_64bit() {
#ifdef _WIN64
    return TRUE;
#else
    return FALSE;
#endif
}