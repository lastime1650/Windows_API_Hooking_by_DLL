#include "pch.h"
#include "ACCESS_MASK_to_str_.h"

#define ACCESS_MASK_CHAR_BUFF_SIZE 512

PCHAR AccessMaskToString(DWORD accessMask, ULONG32* opt_output_strlen) {
    //printf("accessMask -> %d\n", accessMask);
    PCHAR buffer = (PCHAR)malloc(ACCESS_MASK_CHAR_BUFF_SIZE);
    memset(buffer, 0, ACCESS_MASK_CHAR_BUFF_SIZE);

    // 각 권한에 대한 문자열 매핑 및 추가
    if (accessMask & GENERIC_READ) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "GENERIC_READ | ");
    }
    if (accessMask & GENERIC_WRITE) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "GENERIC_WRITE | ");
    }
    if (accessMask & GENERIC_EXECUTE) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "GENERIC_EXECUTE | ");
    }
    if (accessMask & GENERIC_ALL) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "GENERIC_ALL | ");
    }
    if (accessMask & FILE_GENERIC_READ) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_GENERIC_READ | ");
    }
    if (accessMask & FILE_GENERIC_WRITE) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_GENERIC_WRITE | ");
    }
    if (accessMask & FILE_GENERIC_EXECUTE) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_GENERIC_EXECUTE | ");
    }
    if (accessMask & FILE_READ_DATA) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_READ_DATA | ");
    }
    if (accessMask & FILE_WRITE_DATA) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_WRITE_DATA | ");
    }
    if (accessMask & FILE_APPEND_DATA) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_APPEND_DATA | ");
    }
    if (accessMask & FILE_READ_EA) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_READ_EA | ");
    }
    if (accessMask & FILE_WRITE_EA) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_WRITE_EA | ");
    }
    if (accessMask & FILE_EXECUTE) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_EXECUTE | ");
    }
    if (accessMask & FILE_DELETE_CHILD) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_DELETE_CHILD | ");
    }
    if (accessMask & FILE_READ_ATTRIBUTES) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_READ_ATTRIBUTES | ");
    }
    if (accessMask & FILE_WRITE_ATTRIBUTES) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "FILE_WRITE_ATTRIBUTES | ");
    }
    if (accessMask & DELETE) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "DELETE | ");
    }
    if (accessMask & READ_CONTROL) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "READ_CONTROL | ");
    }
    if (accessMask & WRITE_DAC) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "WRITE_DAC | ");
    }
    if (accessMask & WRITE_OWNER) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "WRITE_OWNER | ");
    }
    if (accessMask & SYNCHRONIZE) {
        strcat_s(buffer, ACCESS_MASK_CHAR_BUFF_SIZE, "SYNCHRONIZE | ");
    }


    // 마지막 " | " 제거
    size_t len = strlen(buffer);
    if (len > 0) {
        buffer[len - 3] = '\0'; // 마지막 3 문자 (" | ") 제거
    }

    if (opt_output_strlen)
        *opt_output_strlen = (ULONG32)strlen(buffer);

    return buffer;
}

VOID FREE_AccessMaskToString(PCHAR Str) {
    free(Str);
}