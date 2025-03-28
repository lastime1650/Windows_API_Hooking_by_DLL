#include "pch.h"
#include "Hooking_Handler.h"


#include "Inline_hook.h"
#include "DynamicLength.h" // API후크핸들러 --> 연결리스트생성 --> 길이기반 데이터
#include "Kernel_Communicate_.h" //커널에 전달

HANDLE my_PID = (HANDLE)GetCurrentProcessId();

NTSTATUS NTAPI HOOK_NtCreateUserProcess(
    OUT PHANDLE ProcessHandle,
    OUT PHANDLE ThreadHandle,
    IN PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    IN POBJECT_ATTRIBUTES ProcessObjectAttributes,
    IN POBJECT_ATTRIBUTES ThreadObjectAttributes,
    IN ULONG ProcessFlags,
    IN ULONG ThreadFlags,
    IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    IN PVOID CreateInfo, // PPROCESS_CREATE_INFO
    IN PVOID AttributeList // PPS_ATTRIBUTE_LIST
) {
    NTSTATUS status = 0x0;

    // 1. 이 핸들러/API 에 해당하는 HOOK_INFO가져오기
    PHOOK_info my_info = search_my_info(HOOK_NtCreateUserProcess);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    // 2. 복구하기
    if (Recovering(my_info)) {

        PLinkedListNode StartNode = NULL, CurrentNode = NULL;

        // 4. Core Server에 전달하기 위한 인자를 선별하고, "먼저 연결리스트 구현"
        
        StartNode = CreateListNode((PUCHAR) & my_PID, sizeof(my_PID), (PCHAR)"my_PID: ");
        CurrentNode = StartNode;

        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NtCreateUserProcess", sizeof("NtCreateUserProcess"), (PCHAR)"API_NAME:");

        CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, &ProcessParameters->CommandLine, (PCHAR)"CommandLine:");

        CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, &ProcessParameters->ImagePathName, (PCHAR)"ImagePathName:");

        // 원본 API 호출하고 결과 받기
        status = ((NtCreateUserProcess_t)my_info->Original_API_Address)(
            ProcessHandle,
            ThreadHandle,
            ProcessSecurityDescriptor,
            ThreadSecurityDescriptor,
            ProcessObjectAttributes,
            ThreadObjectAttributes,
            ProcessFlags,
            ThreadFlags,
            ProcessParameters,
            CreateInfo,
            AttributeList
            );

        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        // 5. '길이기반 데이터'로 변환한다. ( 한 덩어리로 압축 ) 
        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);

        // 6. 이전 연결리스트는 제거한다.
        RemoveAllNode(StartNode);

        // 7. 커널에 데이터를 전달한다.
        Send_API_log((PCHAR)"NtCreateUserProcess", DynData, DynDataSize);

        // 8. '길이기반 데이터'를 해제한다.
        Free_Dynamic_Data_2_lengthbased(DynData);

        

        //  다시 후킹하기
        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);

    return status;
}


NTSTATUS NTAPI HOOK_NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
) {
    NTSTATUS status = 0x0;

    // 1. 이 핸들러/API 에 해당하는 HOOK_INFO가져오기
    PHOOK_info my_info = search_my_info(HOOK_NtOpenProcess);
    printf("info 찾음 -> 'search_my_info' -> %p \n", my_info);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    // 2. 복구하기
    if (Recovering(my_info)) {


        PLinkedListNode StartNode = NULL, CurrentNode = NULL;

        // 4. Core Server에 전달하기 위한 인자를 선별하고, "먼저 연결리스트 구현"
        StartNode = CreateListNode((PUCHAR)&my_PID, sizeof(my_PID), (PCHAR)"my_PID: ");
        CurrentNode = StartNode;

        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NtOpenProcess", sizeof("NtOpenProcess"), (PCHAR)"API_NAME:");

        CurrentNode = AppendListNode_with_ACCESSMASK(CurrentNode, DesiredAccess);

        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&ClientId->UniqueProcess, sizeof(ClientId->UniqueProcess), (PCHAR)"ProcessID:");

        //  원본 API 호출하고 결과 받기
        status = ((NtOpenProcess_t)my_info->Original_API_Address)(
            ProcessHandle,
            DesiredAccess,
            ObjectAttributes,
            ClientId);

        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        // 5. '길이기반 데이터'로 변환한다. ( 한 덩어리로 압축 )
        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);

        // 6. 이전 연결리스트는 제거한다.
        RemoveAllNode(StartNode);

        // 7. 커널에 데이터를 전달한다.
        Send_API_log((PCHAR)"NtOpenProcess", DynData, DynDataSize);

        // 8. '길이기반 데이터'를 해제한다.
        Free_Dynamic_Data_2_lengthbased(DynData);

        

        //  다시 후킹하기
        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);

    return status;
}
/*
NTSTATUS NTAPI HOOK_NtCreateThread(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ProcessHandle,
    OUT PCLIENT_ID ClientId,
    IN PCONTEXT ThreadContext,
    IN PINITIAL_TEB InitialTeb,
    IN BOOLEAN CreateSuspended
) {
    return 0;
}

NTSTATUS NTAPI HOOK_NtOpenThread(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
) {
    return 0;
}

NTSTATUS NTAPI HOOK_NtResumeThread(
    IN HANDLE ThreadHandle,
    OUT PULONG SuspendCount OPTIONAL
) {
    return 0;
}

NTSTATUS NTAPI HOOK_NtSuspendThread(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL
) {
    return 0;
}
*/
NTSTATUS NTAPI HOOK_NtTerminateProcess(
    IN HANDLE ProcessHandle,
    IN NTSTATUS ExitStatus
) {
    NTSTATUS status = 0x0;

    // 1. 이 핸들러/API 에 해당하는 HOOK_INFO가져오기
    PHOOK_info my_info = search_my_info(HOOK_NtTerminateProcess);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    // 2. 복구하기
    if (Recovering(my_info)) {
        

        PLinkedListNode StartNode = NULL, CurrentNode = NULL;

        // 4. Core Server에 전달하기 위한 인자를 선별하고, "먼저 연결리스트 구현"
        StartNode = CreateListNode((PUCHAR)"NtTerminateProcess", sizeof("NtTerminateProcess"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // ProcessHandle을 PID로 변환하여 전달 (필요한 경우)
        
        DWORD processId = GetProcessId(ProcessHandle);
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&processId, sizeof(processId), (PCHAR)"ProcessID:");

        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&ExitStatus, sizeof(ExitStatus), (PCHAR)"ExitStatus:");

        //  원본 API 호출하고 결과 받기
        status = ((NtTerminateProcess_t)my_info->Original_API_Address)(
            ProcessHandle,
            ExitStatus
            );

        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        // 5. '길이기반 데이터'로 변환한다. ( 한 덩어리로 압축 )
        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);

        // 6. 이전 연결리스트는 제거한다.
        RemoveAllNode(StartNode);

        // 7. 커널에 데이터를 전달한다.
        Send_API_log((PCHAR)"NtTerminateProcess", DynData, DynDataSize);

        // 8. '길이기반 데이터'를 해제한다.
        Free_Dynamic_Data_2_lengthbased(DynData);


        //  다시 후킹하기
        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);

    return status;
}

NTSTATUS NTAPI HOOK_NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
) {

    return 0;
}

NTSTATUS NTAPI HOOK_NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
) {
    return 0;
}

NTSTATUS NTAPI HOOK_NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PULONG NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection
) {
    return 0;
}

NTSTATUS NTAPI HOOK_NtReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL
) {
    return 0;
}

NTSTATUS NTAPI HOOK_NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
) {
    return 0;
}

NTSTATUS NTAPI HOOK_NtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtQueryInformationProcess);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        

        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtQueryInformationProcess", sizeof("NtQueryInformationProcess"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // ProcessHandle -> PID
        DWORD processId = GetProcessId(ProcessHandle);
        if (processId != 0) {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&processId, sizeof(processId), (PCHAR)"ProcessID:");
        }
        else {
            DWORD defaultProcessId = 0;
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&defaultProcessId, sizeof(defaultProcessId), (PCHAR)"ProcessID (Error):");
            printf("Error: Could not get Process ID from Handle in NtQueryInformationProcess!\n");
        }

        // ProcessInformationClass
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&ProcessInformationClass, sizeof(ProcessInformationClass), (PCHAR)"ProcessInformationClass:");

        // ProcessInformationLength
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&ProcessInformationLength, sizeof(ProcessInformationLength), (PCHAR)"ProcessInformationLength:");

        status = ((NtQueryInformationProcess_t)my_info->Original_API_Address)(
            ProcessHandle,
            ProcessInformationClass,
            ProcessInformation,
            ProcessInformationLength,
            ReturnLength
            );

        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtQueryInformationProcess", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

NTSTATUS NTAPI HOOK_NtQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
) {
    return 0;
}

NTSTATUS NTAPI HOOK_NtCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtCreateFile);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        printf(" 'DesiredAccess-> %d' \n", (DWORD)DesiredAccess);
        

        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtCreateFile", sizeof("NtCreateFile"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DesiredAccess
        CurrentNode = AppendListNode_with_ACCESSMASK(CurrentNode, DesiredAccess);

        // ObjectAttributes->ObjectName (UNICODE_STRING)
        if (ObjectAttributes && ObjectAttributes->ObjectName) {
            CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ObjectAttributes->ObjectName, (PCHAR)"FileName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"FileName: (NULL)");
        }

        status = ((NtCreateFile_t)my_info->Original_API_Address)(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            AllocationSize,
            FileAttributes,
            ShareAccess,
            CreateDisposition,
            CreateOptions,
            EaBuffer,
            EaLength
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtCreateFile", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}
// NtOpenFile
NTSTATUS NTAPI HOOK_NtOpenFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtOpenFile);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        

        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtOpenFile", sizeof("NtOpenFile"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DesiredAccess
        CurrentNode = AppendListNode_with_ACCESSMASK(CurrentNode, DesiredAccess);

        // ObjectAttributes->ObjectName (UNICODE_STRING)
        if (ObjectAttributes && ObjectAttributes->ObjectName) {
            CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ObjectAttributes->ObjectName, (PCHAR)"FileName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"FileName: (NULL)");
        }

        // ShareAccess, OpenOptions 등 다른 필요한 정보 추가
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&ShareAccess, sizeof(ShareAccess), (PCHAR)"ShareAccess:");
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&OpenOptions, sizeof(OpenOptions), (PCHAR)"OpenOptions:");

        status = ((NtOpenFile_t)my_info->Original_API_Address)(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            ShareAccess,
            OpenOptions
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtOpenFile", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtDeviceIoControlFile (IOCTL 코드를 특정하지 않으므로 기본적인 정보만 기록)
NTSTATUS NTAPI HOOK_NtDeviceIoControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG IoControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtDeviceIoControlFile);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        

        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtDeviceIoControlFile", sizeof("NtDeviceIoControlFile"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // FileHandle -> 파일 이름 (가능한 경우)
        WCHAR fileName[256];
        if (GetFinalPathNameByHandleW(FileHandle, fileName, 256, FILE_NAME_NORMALIZED)) {
            // Convert to ANSI
            char ansiFileName[256];
            WideCharToMultiByte(CP_ACP, 0, fileName, -1, ansiFileName, 256, NULL, NULL);
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)ansiFileName, strlen(ansiFileName) + 1, (PCHAR)"FileName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"Unknown", sizeof("Unknown"), (PCHAR)"FileName: Unknown");
        }

        // IoControlCode
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&IoControlCode, sizeof(IoControlCode), (PCHAR)"IoControlCode:");

        // InputBufferLength, OutputBufferLength
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&InputBufferLength, sizeof(InputBufferLength), (PCHAR)"InputBufferLength:");
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&OutputBufferLength, sizeof(OutputBufferLength), (PCHAR)"OutputBufferLength:");

        status = ((NtDeviceIoControlFile_t)my_info->Original_API_Address)(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            IoControlCode,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtDeviceIoControlFile", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtQueryDirectoryFile
NTSTATUS NTAPI HOOK_NtQueryDirectoryFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN PUNICODE_STRING FileName OPTIONAL,
    IN BOOLEAN RestartScan
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtQueryDirectoryFile);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtQueryDirectoryFile", sizeof("NtQueryDirectoryFile"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // FileHandle -> 파일 이름 (가능한 경우)
        WCHAR fileNameBuffer[256];
        if (GetFinalPathNameByHandleW(FileHandle, fileNameBuffer, 256, FILE_NAME_NORMALIZED)) {
            // Convert to ANSI
            char ansiFileName[256];
            WideCharToMultiByte(CP_ACP, 0, fileNameBuffer, -1, ansiFileName, 256, NULL, NULL);
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)ansiFileName, strlen(ansiFileName) + 1, (PCHAR)"FileName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"Unknown", sizeof("Unknown"), (PCHAR)"FileName: Unknown");
        }

        // FileInformationClass
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&FileInformationClass, sizeof(FileInformationClass), (PCHAR)"FileInformationClass:");

        // FileName (UNICODE_STRING)
        if (FileName) {
            CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, FileName, (PCHAR)"SearchPattern:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"SearchPattern: (NULL)");
        }

        status = ((NtQueryDirectoryFile_t)my_info->Original_API_Address)(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass,
            ReturnSingleEntry,
            FileName,
            RestartScan
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtQueryDirectoryFile", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtLoadDriver
NTSTATUS NTAPI HOOK_NtLoadDriver(
    IN PUNICODE_STRING DriverServiceName
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtLoadDriver);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtLoadDriver", sizeof("NtLoadDriver"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DriverServiceName (UNICODE_STRING)
        CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, DriverServiceName, (PCHAR)"DriverServiceName:");

        status = ((NtLoadDriver_t)my_info->Original_API_Address)(
            DriverServiceName
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtLoadDriver", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtUnloadDriver
NTSTATUS NTAPI HOOK_NtUnloadDriver(
    IN PUNICODE_STRING DriverServiceName
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtUnloadDriver);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtUnloadDriver", sizeof("NtUnloadDriver"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DriverServiceName (UNICODE_STRING)
        CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, DriverServiceName, (PCHAR)"DriverServiceName:");

        status = ((NtUnloadDriver_t)my_info->Original_API_Address)(
            DriverServiceName
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtUnloadDriver", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtCreateSection
NTSTATUS NTAPI HOOK_NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtCreateSection);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtCreateSection", sizeof("NtCreateSection"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DesiredAccess
        CurrentNode = AppendListNode_with_ACCESSMASK(CurrentNode, DesiredAccess);

        // ObjectName (UNICODE_STRING)
        if (ObjectAttributes && ObjectAttributes->ObjectName) {
            CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ObjectAttributes->ObjectName, (PCHAR)"SectionName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"SectionName: (NULL)");
        }

        // SectionPageProtection, AllocationAttributes
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&SectionPageProtection, sizeof(SectionPageProtection), (PCHAR)"SectionPageProtection:");
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&AllocationAttributes, sizeof(AllocationAttributes), (PCHAR)"AllocationAttributes:");

        // FileHandle -> 파일 이름 (가능한 경우)
        if (FileHandle) {
            WCHAR fileNameBuffer[256];
            if (GetFinalPathNameByHandleW(FileHandle, fileNameBuffer, 256, FILE_NAME_NORMALIZED)) {
                // Convert to ANSI
                char ansiFileName[256];
                WideCharToMultiByte(CP_ACP, 0, fileNameBuffer, -1, ansiFileName, 256, NULL, NULL);
                CurrentNode = AppendListNode(CurrentNode, (PUCHAR)ansiFileName, strlen(ansiFileName) + 1, (PCHAR)"FileHandleName:");
            }
            else {
                CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"Unknown", sizeof("Unknown"), (PCHAR)"FileHandleName: Unknown");
            }
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"FileHandleName: (NULL)");
        }

        status = ((NtCreateSection_t)my_info->Original_API_Address)(
            SectionHandle,
            DesiredAccess,
            ObjectAttributes,
            MaximumSize,
            SectionPageProtection,
            AllocationAttributes,
            FileHandle
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtCreateSection", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtOpenSection
NTSTATUS NTAPI HOOK_NtOpenSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtOpenSection);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtOpenSection", sizeof("NtOpenSection"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DesiredAccess
        CurrentNode = AppendListNode_with_ACCESSMASK(CurrentNode, DesiredAccess);

        // ObjectName (UNICODE_STRING)
        if (ObjectAttributes && ObjectAttributes->ObjectName) {
            CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ObjectAttributes->ObjectName, (PCHAR)"SectionName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"SectionName: (NULL)");
        }

        status = ((NtOpenSection_t)my_info->Original_API_Address)(
            SectionHandle,
            DesiredAccess,
            ObjectAttributes
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtOpenSection", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtMapViewOfSection
NTSTATUS NTAPI HOOK_NtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtMapViewOfSection);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtMapViewOfSection", sizeof("NtMapViewOfSection"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // SectionHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&SectionHandle, sizeof(SectionHandle), (PCHAR)"SectionHandle:");

        // ProcessHandle -> PID
        DWORD processId = GetProcessId(ProcessHandle);
        if (processId != 0) {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&processId, sizeof(processId), (PCHAR)"ProcessID:");
        }
        else {
            DWORD defaultProcessId = 0;
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&defaultProcessId, sizeof(defaultProcessId), (PCHAR)"ProcessID (Error):");
            printf("Error: Could not get Process ID from Handle in NtMapViewOfSection!\n");
        }


        // CommitSize, ViewSize
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&CommitSize, sizeof(CommitSize), (PCHAR)"CommitSize:");
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&ViewSize, sizeof(ViewSize), (PCHAR)"ViewSize:");

        // AllocationType, Win32Protect
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&AllocationType, sizeof(AllocationType), (PCHAR)"AllocationType:");
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Win32Protect, sizeof(Win32Protect), (PCHAR)"Win32Protect:");

        status = ((NtMapViewOfSection_t)my_info->Original_API_Address)(
            SectionHandle,
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            CommitSize,
            SectionOffset,
            ViewSize,
            InheritDisposition,
            AllocationType,
            Win32Protect
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtMapViewOfSection", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtUnmapViewOfSection
NTSTATUS NTAPI HOOK_NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtUnmapViewOfSection);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtUnmapViewOfSection", sizeof("NtUnmapViewOfSection"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // ProcessHandle -> PID
        DWORD processId = GetProcessId(ProcessHandle);
        if (processId != 0) {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&processId, sizeof(processId), (PCHAR)"ProcessID:");
        }
        else {
            DWORD defaultProcessId = 0;
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&defaultProcessId, sizeof(defaultProcessId), (PCHAR)"ProcessID (Error):");
            printf("Error: Could not get Process ID from Handle in NtUnmapViewOfSection!\n");
        }


        status = ((NtUnmapViewOfSection_t)my_info->Original_API_Address)(
            ProcessHandle,
            BaseAddress
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtUnmapViewOfSection", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtQuerySystemInformation
NTSTATUS NTAPI HOOK_NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtQuerySystemInformation);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtQuerySystemInformation", sizeof("NtQuerySystemInformation"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // SystemInformationClass
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&SystemInformationClass, sizeof(SystemInformationClass), (PCHAR)"SystemInformationClass:");

        // SystemInformationLength
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&SystemInformationLength, sizeof(SystemInformationLength), (PCHAR)"SystemInformationLength:");

        status = ((NtQuerySystemInformation_t)my_info->Original_API_Address)(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtQuerySystemInformation", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtSetSystemInformation
NTSTATUS NTAPI HOOK_NtSetSystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtSetSystemInformation);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtSetSystemInformation", sizeof("NtSetSystemInformation"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // SystemInformationClass
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&SystemInformationClass, sizeof(SystemInformationClass), (PCHAR)"SystemInformationClass:");

        // SystemInformationLength
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&SystemInformationLength, sizeof(SystemInformationLength), (PCHAR)"SystemInformationLength:");

        status = ((NtSetSystemInformation_t)my_info->Original_API_Address)(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtSetSystemInformation", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// LdrLoadDll
NTSTATUS NTAPI HOOK_LdrLoadDll(
    IN PWSTR SearchPath OPTIONAL,
    IN PULONG DllCharacteristics OPTIONAL,
    IN PUNICODE_STRING DllName,
    OUT PVOID* DllHandle
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_LdrLoadDll);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"LdrLoadDll", sizeof("LdrLoadDll"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DllName (UNICODE_STRING)
        CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, DllName, (PCHAR)"DllName:");

        status = ((LdrLoadDll_t)my_info->Original_API_Address)(
            SearchPath,
            DllCharacteristics,
            DllName,
            DllHandle
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"LdrLoadDll", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// LdrUnloadDll
NTSTATUS NTAPI HOOK_LdrUnloadDll(
    IN PVOID DllHandle
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_LdrUnloadDll);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
       
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"LdrUnloadDll", sizeof("LdrUnloadDll"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DllHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&DllHandle, sizeof(DllHandle), (PCHAR)"DllHandle:");

        status = ((LdrUnloadDll_t)my_info->Original_API_Address)(
            DllHandle
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"LdrUnloadDll", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// LdrGetProcedureAddress
NTSTATUS NTAPI HOOK_LdrGetProcedureAddress(
    IN PVOID DllHandle,
    IN PANSI_STRING ProcedureName OPTIONAL,
    IN ULONG Ordinal OPTIONAL,
    OUT PVOID* ProcedureAddress
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_LdrGetProcedureAddress);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"LdrGetProcedureAddress", sizeof("LdrGetProcedureAddress"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DllHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&DllHandle, sizeof(DllHandle), (PCHAR)"DllHandle:");

        // ProcedureName (ANSI_STRING)
        if (ProcedureName && ProcedureName->Buffer) {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)ProcedureName->Buffer, ProcedureName->Length + 1, (PCHAR)"ProcedureName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"Ordinal", sizeof("Ordinal"), (PCHAR)"ProcedureName: (Ordinal)");
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Ordinal, sizeof(Ordinal), (PCHAR)"OrdinalValue:");
        }

        status = ((LdrGetProcedureAddress_t)my_info->Original_API_Address)(
            DllHandle,
            ProcedureName,
            Ordinal,
            ProcedureAddress
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"LdrGetProcedureAddress", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// LdrGetDllHandle
NTSTATUS NTAPI HOOK_LdrGetDllHandle(
    IN PWSTR DllPath OPTIONAL,
    IN PULONG DllCharacteristics OPTIONAL,
    IN PUNICODE_STRING DllName,
    OUT PVOID* DllHandle
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_LdrGetDllHandle);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
       
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"LdrGetDllHandle", sizeof("LdrGetDllHandle"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DllName (UNICODE_STRING)
        CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, DllName, (PCHAR)"DllName:");

        status = ((LdrGetDllHandle_t)my_info->Original_API_Address)(
            DllPath,
            DllCharacteristics,
            DllName,
            DllHandle
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"LdrGetDllHandle", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}
// NtCreateKey
NTSTATUS NTAPI HOOK_NtCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG TitleIndex,
    IN PUNICODE_STRING Class OPTIONAL,
    IN ULONG CreateOptions,
    OUT PULONG Disposition OPTIONAL
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtCreateKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtCreateKey", sizeof("NtCreateKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DesiredAccess
        CurrentNode = AppendListNode_with_ACCESSMASK(CurrentNode, DesiredAccess);

        // ObjectName (UNICODE_STRING)
        if (ObjectAttributes && ObjectAttributes->ObjectName) {
            CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ObjectAttributes->ObjectName, (PCHAR)"KeyName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"KeyName: (NULL)");
        }

        // Class (UNICODE_STRING)
        if (Class) {
            CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, Class, (PCHAR)"Class:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"Class: (NULL)");
        }

        // CreateOptions
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&CreateOptions, sizeof(CreateOptions), (PCHAR)"CreateOptions:");

        status = ((NtCreateKey_t)my_info->Original_API_Address)(
            KeyHandle,
            DesiredAccess,
            ObjectAttributes,
            TitleIndex,
            Class,
            CreateOptions,
            Disposition
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtCreateKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtOpenKey
NTSTATUS NTAPI HOOK_NtOpenKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtOpenKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtOpenKey", sizeof("NtOpenKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // DesiredAccess
        CurrentNode = AppendListNode_with_ACCESSMASK(CurrentNode, DesiredAccess);

        // ObjectName (UNICODE_STRING)
        if (ObjectAttributes && ObjectAttributes->ObjectName) {
            CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ObjectAttributes->ObjectName, (PCHAR)"KeyName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"KeyName: (NULL)");
        }

        status = ((NtOpenKey_t)my_info->Original_API_Address)(
            KeyHandle,
            DesiredAccess,
            ObjectAttributes
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtOpenKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtSetValueKey
NTSTATUS NTAPI HOOK_NtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex,
    IN ULONG Type,
    IN PVOID Data,
    IN ULONG DataSize
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtSetValueKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtSetValueKey", sizeof("NtSetValueKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // KeyHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyHandle, sizeof(KeyHandle), (PCHAR)"KeyHandle:");

        // ValueName (UNICODE_STRING)
        CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ValueName, (PCHAR)"ValueName:");

        // Type
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Type, sizeof(Type), (PCHAR)"Type:");

        // DataSize
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&DataSize, sizeof(DataSize), (PCHAR)"DataSize:");

        status = ((NtSetValueKey_t)my_info->Original_API_Address)(
            KeyHandle,
            ValueName,
            TitleIndex,
            Type,
            Data,
            DataSize
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtSetValueKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtDeleteKey
NTSTATUS NTAPI HOOK_NtDeleteKey(
    IN HANDLE KeyHandle
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtDeleteKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtDeleteKey", sizeof("NtDeleteKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // KeyHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyHandle, sizeof(KeyHandle), (PCHAR)"KeyHandle:");

        status = ((NtDeleteKey_t)my_info->Original_API_Address)(
            KeyHandle
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtDeleteKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtDeleteValueKey
NTSTATUS NTAPI HOOK_NtDeleteValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtDeleteValueKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtDeleteValueKey", sizeof("NtDeleteValueKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // KeyHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyHandle, sizeof(KeyHandle), (PCHAR)"KeyHandle:");

        // ValueName (UNICODE_STRING)
        CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ValueName, (PCHAR)"ValueName:");

        status = ((NtDeleteValueKey_t)my_info->Original_API_Address)(
            KeyHandle,
            ValueName
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtDeleteValueKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtQueryKey
NTSTATUS NTAPI HOOK_NtQueryKey(
    IN HANDLE KeyHandle,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID KeyInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtQueryKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtQueryKey", sizeof("NtQueryKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // KeyHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyHandle, sizeof(KeyHandle), (PCHAR)"KeyHandle:");

        // KeyInformationClass
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyInformationClass, sizeof(KeyInformationClass), (PCHAR)"KeyInformationClass:");

        // Length
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Length, sizeof(Length), (PCHAR)"Length:");

        status = ((NtQueryKey_t)my_info->Original_API_Address)(
            KeyHandle,
            KeyInformationClass,
            KeyInformation,
            Length,
            ResultLength
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtQueryKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtQueryValueKey
NTSTATUS NTAPI HOOK_NtQueryValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT PVOID KeyValueInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtQueryValueKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtQueryValueKey", sizeof("NtQueryValueKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // KeyHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyHandle, sizeof(KeyHandle), (PCHAR)"KeyHandle:");

        // ValueName (UNICODE_STRING)
        CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ValueName, (PCHAR)"ValueName:");

        // KeyValueInformationClass
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyValueInformationClass, sizeof(KeyValueInformationClass), (PCHAR)"KeyValueInformationClass:");

        // Length
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Length, sizeof(Length), (PCHAR)"Length:");

        status = ((NtQueryValueKey_t)my_info->Original_API_Address)(
            KeyHandle,
            ValueName,
            KeyValueInformationClass,
            KeyValueInformation,
            Length,
            ResultLength
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtQueryValueKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtEnumerateKey
NTSTATUS NTAPI HOOK_NtEnumerateKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID KeyInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtEnumerateKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtEnumerateKey", sizeof("NtEnumerateKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // KeyHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyHandle, sizeof(KeyHandle), (PCHAR)"KeyHandle:");

        // Index
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Index, sizeof(Index), (PCHAR)"Index:");

        // KeyInformationClass
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyInformationClass, sizeof(KeyInformationClass), (PCHAR)"KeyInformationClass:");

        // Length
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Length, sizeof(Length), (PCHAR)"Length:");

        status = ((NtEnumerateKey_t)my_info->Original_API_Address)(
            KeyHandle,
            Index,
            KeyInformationClass,
            KeyInformation,
            Length,
            ResultLength
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtEnumerateKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtEnumerateValueKey
NTSTATUS NTAPI HOOK_NtEnumerateValueKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT PVOID KeyValueInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtEnumerateValueKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
       
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtEnumerateValueKey", sizeof("NtEnumerateValueKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // KeyHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyHandle, sizeof(KeyHandle), (PCHAR)"KeyHandle:");

        // Index
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Index, sizeof(Index), (PCHAR)"Index:");

        // KeyValueInformationClass
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyValueInformationClass, sizeof(KeyValueInformationClass), (PCHAR)"KeyValueInformationClass:");

        // Length
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Length, sizeof(Length), (PCHAR)"Length:");

        status = ((NtEnumerateValueKey_t)my_info->Original_API_Address)(
            KeyHandle,
            Index,
            KeyValueInformationClass,
            KeyValueInformation,
            Length,
            ResultLength
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtEnumerateValueKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtFlushKey
NTSTATUS NTAPI HOOK_NtFlushKey(
    IN HANDLE KeyHandle
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtFlushKey);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtFlushKey", sizeof("NtFlushKey"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // KeyHandle
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&KeyHandle, sizeof(KeyHandle), (PCHAR)"KeyHandle:");

        status = ((NtFlushKey_t)my_info->Original_API_Address)(
            KeyHandle
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtFlushKey", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtReadFile
NTSTATUS NTAPI HOOK_NtReadFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtReadFile);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtReadFile", sizeof("NtReadFile"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // FileHandle -> 파일 이름 (가능한 경우)
        WCHAR fileNameBuffer[256];
        if (GetFinalPathNameByHandleW(FileHandle, fileNameBuffer, 256, FILE_NAME_NORMALIZED)) {
            // Convert to ANSI
            char ansiFileName[256];
            WideCharToMultiByte(CP_ACP, 0, fileNameBuffer, -1, ansiFileName, 256, NULL, NULL);
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)ansiFileName, strlen(ansiFileName) + 1, (PCHAR)"FileName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"Unknown", sizeof("Unknown"), (PCHAR)"FileName: Unknown");
        }

        // Length
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Length, sizeof(Length), (PCHAR)"Length:");

        // ByteOffset
        if (ByteOffset) {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&ByteOffset->QuadPart, sizeof(ByteOffset->QuadPart), (PCHAR)"ByteOffset:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"ByteOffset: (NULL)");
        }

        status = ((NtReadFile_t)my_info->Original_API_Address)(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            Buffer,
            Length,
            ByteOffset,
            Key
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtReadFile", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtWriteFile
NTSTATUS NTAPI HOOK_NtWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtWriteFile);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtWriteFile", sizeof("NtWriteFile"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // FileHandle -> 파일 이름 (가능한 경우)
        WCHAR fileNameBuffer[256];
        if (GetFinalPathNameByHandleW(FileHandle, fileNameBuffer, 256, FILE_NAME_NORMALIZED)) {
            // Convert to ANSI
            char ansiFileName[256];
            WideCharToMultiByte(CP_ACP, 0, fileNameBuffer, -1, ansiFileName, 256, NULL, NULL);
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)ansiFileName, strlen(ansiFileName) + 1, (PCHAR)"FileName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"Unknown", sizeof("Unknown"), (PCHAR)"FileName: Unknown");
        }

        // Length
        CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&Length, sizeof(Length), (PCHAR)"Length:");

        // ByteOffset
        if (ByteOffset) {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&ByteOffset->QuadPart, sizeof(ByteOffset->QuadPart), (PCHAR)"ByteOffset:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"ByteOffset: (NULL)");
        }

        status = ((NtWriteFile_t)my_info->Original_API_Address)(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            Buffer,
            Length,
            ByteOffset,
            Key
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtWriteFile", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtDeleteFile
NTSTATUS NTAPI HOOK_NtDeleteFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtDeleteFile);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtDeleteFile", sizeof("NtDeleteFile"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // ObjectName (UNICODE_STRING)
        if (ObjectAttributes && ObjectAttributes->ObjectName) {
            CurrentNode = AppendListNode_with_UNICODE_STRING(CurrentNode, ObjectAttributes->ObjectName, (PCHAR)"FileName:");
        }
        else {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)"NULL", sizeof("NULL"), (PCHAR)"FileName: (NULL)");
        }

        status = ((NtDeleteFile_t)my_info->Original_API_Address)(
            ObjectAttributes
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtDeleteFile", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtSuspendProcess (이어서)
NTSTATUS NTAPI HOOK_NtSuspendProcess(
    IN HANDLE ProcessHandle
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtSuspendProcess);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtSuspendProcess", sizeof("NtSuspendProcess"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // ProcessHandle -> PID
        DWORD processId = GetProcessId(ProcessHandle);
        if (processId != 0) {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&processId, sizeof(processId), (PCHAR)"ProcessID:");
        }
        else {
            DWORD defaultProcessId = 0;
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&defaultProcessId, sizeof(defaultProcessId), (PCHAR)"ProcessID (Error):");
            printf("Error: Could not get Process ID from Handle in NtSuspendProcess!\n");
        }

        status = ((NtSuspendProcess_t)my_info->Original_API_Address)(
            ProcessHandle
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtSuspendProcess", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}

// NtResumeProcess
NTSTATUS NTAPI HOOK_NtResumeProcess(
    IN HANDLE ProcessHandle
) {
    NTSTATUS status = 0x0;
    PHOOK_info my_info = search_my_info(HOOK_NtResumeProcess);

    WaitForSingleObject(my_info->mutex_handle, INFINITE);

    if (Recovering(my_info)) {
        
        PLinkedListNode StartNode = NULL, CurrentNode = NULL;
        StartNode = CreateListNode((PUCHAR)"NtResumeProcess", sizeof("NtResumeProcess"), (PCHAR)"API_NAME:");
        CurrentNode = StartNode;

        // ProcessHandle -> PID
        DWORD processId = GetProcessId(ProcessHandle);
        if (processId != 0) {
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&processId, sizeof(processId), (PCHAR)"ProcessID:");
        }
        else {
            DWORD defaultProcessId = 0;
            CurrentNode = AppendListNode(CurrentNode, (PUCHAR)&defaultProcessId, sizeof(defaultProcessId), (PCHAR)"ProcessID (Error):");
            printf("Error: Could not get Process ID from Handle in NtResumeProcess!\n");
        }

        status = ((NtResumeProcess_t)my_info->Original_API_Address)(
            ProcessHandle
            );
        CurrentNode = AppendListNode_with_NTSTATUS_2_STRING(CurrentNode, status);

        ULONG32 DynDataSize = 0;
        PUCHAR DynData = Make_Dynamic_Data_2_lengthbased(StartNode, &DynDataSize);
        RemoveAllNode(StartNode);
        Send_API_log((PCHAR)"NtResumeProcess", DynData, DynDataSize);
        Free_Dynamic_Data_2_lengthbased(DynData);

        if (Hooking(my_info->Original_API_Address, my_info->Hook_Address, FALSE))
            printf("다시 후킹완료\n");
    }

    ReleaseMutex(my_info->mutex_handle);
    return status;
}
