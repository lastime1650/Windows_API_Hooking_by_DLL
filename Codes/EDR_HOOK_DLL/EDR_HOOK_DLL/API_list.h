#ifndef API_LIST_H

#include <stdio.h>
#include <Windows.h>
#include "pch.h"

#include "Hooking_Handler.h"

CHAR API_NAME_List[][40] = {
    // 프로세스 및 스레드 관련
    "NtCreateUserProcess",    // 새 사용자 프로세스 생성
    //"NtOpenProcess",          // 기존 프로세스에 대한 핸들 획득
   // "NtCreateThread",         // 새 스레드 생성 (기본)
    //"NtOpenThread",           // 기존 스레드에 대한 핸들 획득
    "NtTerminateProcess",     // 프로세스 종료
    //"NtTerminateThread",      // 스레드 종료
    
    // 메모리 관련 (추가)
    /*
    "NtAllocateVirtualMemory", // 프로세스 가상 메모리 할당
    "NtProtectVirtualMemory",  // 가상 메모리 보호 속성 변경
    "NtFreeVirtualMemory",    // 할당된 가상 메모리 해제
    "NtReadVirtualMemory",     // 다른 프로세스의 메모리 읽기
    "NtWriteVirtualMemory",    // 다른 프로세스의 메모리 쓰기
    "NtMapViewOfSection",      // 메모리 섹션을 뷰에 매핑
    "NtUnmapViewOfSection",    // 메모리 섹션 뷰 매핑 해제
    

    // 파일 및 레지스트리 관련 (추가)
    "NtCreateFile",           // 파일 생성 또는 열기
    "NtOpenFile",             // 기존 파일 열기
    "NtReadFile",             // 파일에서 데이터 읽기
    "NtWriteFile",            // 파일에 데이터 쓰기
    "NtDeleteFile",           // 파일 삭제
    "NtCreateKey",            // 레지스트리 키 생성 또는 열기
    "NtOpenKey",              // 기존 레지스트리 키 열기
    "NtSetValueKey",          // 레지스트리 키 값 설정
    "NtDeleteKey",            // 레지스트리 키 삭제
    "NtDeleteValueKey",       // 레지스트리 키 값 삭제
    "NtQueryKey",            //추가
    "NtQueryValueKey",       //추가
    "NtEnumerateKey",        //추가
    "NtEnumerateValueKey",   //추가
    "NtFlushKey",            //추가

    // 기타 (추가)
    "NtLoadDriver",           // 드라이버 로드
    "NtSetSystemInformation", // 시스템 정보 설정 (보안 설정 변경 등에 사용될 수 있음)
    "NtQuerySystemInformation",// 시스템 정보 쿼리
    "NtQueryInformationProcess", // 프로세스 정보 쿼리
    "NtQueryInformationThread", // 스레드 정보 쿼리

    //"NtSuspendProcess",        // 프로세스 일시 중단
    //"NtResumeProcess",       // 일시 중단된 프로세스 재개
    //"NtSuspendThread",         // 스레드 일시 중단
    //"NtResumeThread",        // 일시 중단된 스레드 재개
    //"NtGetContextThread",     // 스레드 컨텍스트 가져오기
    //"NtSetContextThread",     // 스레드 컨텍스트 설정
    
    //"NtDeviceIoControlFile",    //39 디바이스 IO 컨트롤 파일 작업 수행 (예: 드라이버 통신)
    "NtQueryDirectoryFile",     // 40 디렉터리 내 파일 목록 쿼리
    */
    "LdrLoadDll",               // 41
    "LdrUnloadDll",             // 42
    //"LdrGetProcedureAddress",   // 43
    //"LdrGetDllHandle"           // 44
    
};

PVOID API_Hook_List[] = {
    HOOK_NtCreateUserProcess,    // 0
    HOOK_NtOpenProcess,          // 1
   // HOOK_NtCreateThread,         // 2
    //HOOK_NtOpenThread,           // 3
    HOOK_NtTerminateProcess,     // 4
    //HOOK_NtTerminateThread,      // 5
    /*
    HOOK_NtAllocateVirtualMemory, // 6
    HOOK_NtProtectVirtualMemory,  // 7
    HOOK_NtFreeVirtualMemory,    // 8
    HOOK_NtReadVirtualMemory,     // 9
    HOOK_NtWriteVirtualMemory,    // 10
    HOOK_NtMapViewOfSection,      // 11
    HOOK_NtUnmapViewOfSection,    // 12
    
    HOOK_NtCreateFile,           // 13
    HOOK_NtOpenFile,             // 14
    HOOK_NtReadFile,             // 15
    HOOK_NtWriteFile,            // 16
    HOOK_NtDeleteFile,           // 17
    HOOK_NtCreateKey,            // 18
    HOOK_NtOpenKey,              // 19
    HOOK_NtSetValueKey,          // 20
    HOOK_NtDeleteKey,            // 21
    HOOK_NtDeleteValueKey,       // 22
    HOOK_NtQueryKey,            // 23
    HOOK_NtQueryValueKey,        // 24
    HOOK_NtEnumerateKey,         // 25
    HOOK_NtEnumerateValueKey,    // 26
    HOOK_NtFlushKey,             // 27

    HOOK_NtLoadDriver,           // 28
    HOOK_NtSetSystemInformation, // 29
    HOOK_NtQuerySystemInformation, // 30
    HOOK_NtQueryInformationProcess, // 31
    HOOK_NtQueryInformationThread,  // 32
    
    //HOOK_NtSuspendProcess,         // 33
    //HOOK_NtResumeProcess,        // 34
    //HOOK_NtSuspendThread,          // 35
    //HOOK_NtResumeThread,         // 36
    //HOOK_NtGetContextThread,      // 37
    //HOOK_NtSetContextThread,       // 38

   // HOOK_NtDeviceIoControlFile,      // 39
    HOOK_NtQueryDirectoryFile,        // 40*/
    HOOK_LdrLoadDll,                // 41
    HOOK_LdrUnloadDll,              // 42
    //HOOK_LdrGetProcedureAddress,   // 43
    //HOOK_LdrGetDllHandle             // 44
};

BOOLEAN Init_Start();

#endif