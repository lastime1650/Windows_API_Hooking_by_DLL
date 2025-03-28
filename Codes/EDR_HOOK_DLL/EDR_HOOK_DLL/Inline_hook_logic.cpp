#include "pch.h"
#include "Inline_hook.h"
#include "Check64Bit.h"

#include <stdlib.h>

PHOOK_info Start_Hook_info_LIST_Address = NULL;
PHOOK_info Current_Hook_info_LIST_Address = NULL;


BOOLEAN Hooking(PVOID Original_API_Address, PVOID Hook_Address, BOOLEAN is_create_node) {

    if (!Original_API_Address || !Hook_Address) {
        return FALSE;
    }

    HOOK_info* output = (HOOK_info*)malloc(sizeof(HOOK_info));
    if (!output) {
        return FALSE;
    }
    memset(output, 0, sizeof(HOOK_info));

    // 멤버에 데이터 저장
    output->Hook_Address = Hook_Address;
    output->Original_API_Address = Original_API_Address;

    if (is_64bit()) {
        // 64비트

        BYTE Trampoline_Code[14] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 주소
             0xFF, 0xE0 // JMP RAX
        };

        *((ULONG64*)&Trampoline_Code[2]) = (ULONG64)Hook_Address;

        // 후크 정보 저장
        memcpy(output->Trampoline_HOOK_Code, Trampoline_Code, sizeof(Trampoline_Code));
        output->Trampoline_HOOK_Code_Size = sizeof(Trampoline_Code);

        // 오리지널 데이터 가져오기 (백업)
        memcpy(output->Original_Code, Original_API_Address, sizeof(Trampoline_Code));

    }
    else {
        // 32비트

        // 32비트 (MOV EAX, address; JMP EAX)

        BYTE Trampoline_Code[10] = {
            0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, <address>
            0xFF, 0xE0                   // JMP EAX
        };

        // 후킹 함수 주소 넣기
        *((DWORD*)&Trampoline_Code[1]) = (DWORD)Hook_Address;


        // 후크 정보 저장
        memcpy(output->Trampoline_HOOK_Code, Trampoline_Code, sizeof(Trampoline_Code));
        output->Trampoline_HOOK_Code_Size = sizeof(Trampoline_Code);

        // 오리지널 데이터 가져오기 (백업)
        memcpy(output->Original_Code, Original_API_Address, sizeof(Trampoline_Code));
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /*
        후킹 실행
    */
    // 메모리 쓰기+읽기+실행 으로 변경
    DWORD oldProtect;
    if (!VirtualProtect(Original_API_Address, output->Trampoline_HOOK_Code_Size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        free(output);
        return FALSE;
    }

    // 덮어쓰기
    memcpy(
        Original_API_Address,
        output->Trampoline_HOOK_Code,
        output->Trampoline_HOOK_Code_Size
    );

    // 메모리 보호 복원
    VirtualProtect(Original_API_Address, output->Trampoline_HOOK_Code_Size, oldProtect, &oldProtect);


    if (is_create_node) {

        // mutex 초기화
        output->mutex_handle = CreateMutexA(
            NULL,   // 보안 속성 (일반적으로 NULL)
            FALSE,  // 초기 소유 여부 (FALSE: 어떤 스레드도 소유하지 않음)
            NULL    // 뮤텍스 이름 (선택 사항, 명명된 뮤텍스를 만들 때 사용)
        );

        // 연결리스트 추가
        Appending_info(output);
    }
    else {
        free(output);
    }


    return TRUE;

}


BOOLEAN Recovering(HOOK_info* input_data) {
    // 원본 API 호출을 위한 복원 작업

    DWORD oldProtect;
    if (!VirtualProtect(input_data->Original_API_Address, input_data->Trampoline_HOOK_Code_Size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    // 덮어쓰기
    memcpy(
        input_data->Original_API_Address,
        input_data->Original_Code,
        input_data->Trampoline_HOOK_Code_Size
    );

    // 메모리 보호 복원
    VirtualProtect(input_data->Original_API_Address, input_data->Trampoline_HOOK_Code_Size, oldProtect, &oldProtect);

    return TRUE;
}



/////////
// 연결리스트
PHOOK_info Appending_info(PHOOK_info input) {



    if (Start_Hook_info_LIST_Address == NULL) {
        input->Next_Node = NULL;
        Start_Hook_info_LIST_Address = input;
        Current_Hook_info_LIST_Address = Start_Hook_info_LIST_Address;
    }
    else {
        input->Next_Node = NULL;
        Current_Hook_info_LIST_Address->Next_Node = (PUCHAR)input;
        Current_Hook_info_LIST_Address = input;
    }

    return Current_Hook_info_LIST_Address;
}

PHOOK_info search_my_info(PVOID HOOK_ADDRESS) {

    PHOOK_info current = Start_Hook_info_LIST_Address;
    while (current) {

        if (current->Hook_Address == HOOK_ADDRESS)
            return current;

        current = (PHOOK_info)current->Next_Node;
    }
    return NULL;
}