#ifndef API_LIST_H

#include <stdio.h>
#include <Windows.h>
#include "pch.h"

#include "Hooking_Handler.h"

CHAR API_NAME_List[][40] = {
    // ���μ��� �� ������ ����
    "NtCreateUserProcess",    // �� ����� ���μ��� ����
    //"NtOpenProcess",          // ���� ���μ����� ���� �ڵ� ȹ��
   // "NtCreateThread",         // �� ������ ���� (�⺻)
    //"NtOpenThread",           // ���� �����忡 ���� �ڵ� ȹ��
    "NtTerminateProcess",     // ���μ��� ����
    //"NtTerminateThread",      // ������ ����
    
    // �޸� ���� (�߰�)
    /*
    "NtAllocateVirtualMemory", // ���μ��� ���� �޸� �Ҵ�
    "NtProtectVirtualMemory",  // ���� �޸� ��ȣ �Ӽ� ����
    "NtFreeVirtualMemory",    // �Ҵ�� ���� �޸� ����
    "NtReadVirtualMemory",     // �ٸ� ���μ����� �޸� �б�
    "NtWriteVirtualMemory",    // �ٸ� ���μ����� �޸� ����
    "NtMapViewOfSection",      // �޸� ������ �信 ����
    "NtUnmapViewOfSection",    // �޸� ���� �� ���� ����
    

    // ���� �� ������Ʈ�� ���� (�߰�)
    "NtCreateFile",           // ���� ���� �Ǵ� ����
    "NtOpenFile",             // ���� ���� ����
    "NtReadFile",             // ���Ͽ��� ������ �б�
    "NtWriteFile",            // ���Ͽ� ������ ����
    "NtDeleteFile",           // ���� ����
    "NtCreateKey",            // ������Ʈ�� Ű ���� �Ǵ� ����
    "NtOpenKey",              // ���� ������Ʈ�� Ű ����
    "NtSetValueKey",          // ������Ʈ�� Ű �� ����
    "NtDeleteKey",            // ������Ʈ�� Ű ����
    "NtDeleteValueKey",       // ������Ʈ�� Ű �� ����
    "NtQueryKey",            //�߰�
    "NtQueryValueKey",       //�߰�
    "NtEnumerateKey",        //�߰�
    "NtEnumerateValueKey",   //�߰�
    "NtFlushKey",            //�߰�

    // ��Ÿ (�߰�)
    "NtLoadDriver",           // ����̹� �ε�
    "NtSetSystemInformation", // �ý��� ���� ���� (���� ���� ���� � ���� �� ����)
    "NtQuerySystemInformation",// �ý��� ���� ����
    "NtQueryInformationProcess", // ���μ��� ���� ����
    "NtQueryInformationThread", // ������ ���� ����

    //"NtSuspendProcess",        // ���μ��� �Ͻ� �ߴ�
    //"NtResumeProcess",       // �Ͻ� �ߴܵ� ���μ��� �簳
    //"NtSuspendThread",         // ������ �Ͻ� �ߴ�
    //"NtResumeThread",        // �Ͻ� �ߴܵ� ������ �簳
    //"NtGetContextThread",     // ������ ���ؽ�Ʈ ��������
    //"NtSetContextThread",     // ������ ���ؽ�Ʈ ����
    
    //"NtDeviceIoControlFile",    //39 ����̽� IO ��Ʈ�� ���� �۾� ���� (��: ����̹� ���)
    "NtQueryDirectoryFile",     // 40 ���͸� �� ���� ��� ����
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