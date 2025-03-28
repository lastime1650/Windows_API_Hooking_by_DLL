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

    // ����� ������ ����
    output->Hook_Address = Hook_Address;
    output->Original_API_Address = Original_API_Address;

    if (is_64bit()) {
        // 64��Ʈ

        BYTE Trampoline_Code[14] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, �ּ�
             0xFF, 0xE0 // JMP RAX
        };

        *((ULONG64*)&Trampoline_Code[2]) = (ULONG64)Hook_Address;

        // ��ũ ���� ����
        memcpy(output->Trampoline_HOOK_Code, Trampoline_Code, sizeof(Trampoline_Code));
        output->Trampoline_HOOK_Code_Size = sizeof(Trampoline_Code);

        // �������� ������ �������� (���)
        memcpy(output->Original_Code, Original_API_Address, sizeof(Trampoline_Code));

    }
    else {
        // 32��Ʈ

        // 32��Ʈ (MOV EAX, address; JMP EAX)

        BYTE Trampoline_Code[10] = {
            0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, <address>
            0xFF, 0xE0                   // JMP EAX
        };

        // ��ŷ �Լ� �ּ� �ֱ�
        *((DWORD*)&Trampoline_Code[1]) = (DWORD)Hook_Address;


        // ��ũ ���� ����
        memcpy(output->Trampoline_HOOK_Code, Trampoline_Code, sizeof(Trampoline_Code));
        output->Trampoline_HOOK_Code_Size = sizeof(Trampoline_Code);

        // �������� ������ �������� (���)
        memcpy(output->Original_Code, Original_API_Address, sizeof(Trampoline_Code));
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /*
        ��ŷ ����
    */
    // �޸� ����+�б�+���� ���� ����
    DWORD oldProtect;
    if (!VirtualProtect(Original_API_Address, output->Trampoline_HOOK_Code_Size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        free(output);
        return FALSE;
    }

    // �����
    memcpy(
        Original_API_Address,
        output->Trampoline_HOOK_Code,
        output->Trampoline_HOOK_Code_Size
    );

    // �޸� ��ȣ ����
    VirtualProtect(Original_API_Address, output->Trampoline_HOOK_Code_Size, oldProtect, &oldProtect);


    if (is_create_node) {

        // mutex �ʱ�ȭ
        output->mutex_handle = CreateMutexA(
            NULL,   // ���� �Ӽ� (�Ϲ������� NULL)
            FALSE,  // �ʱ� ���� ���� (FALSE: � �����嵵 �������� ����)
            NULL    // ���ؽ� �̸� (���� ����, ���� ���ؽ��� ���� �� ���)
        );

        // ���Ḯ��Ʈ �߰�
        Appending_info(output);
    }
    else {
        free(output);
    }


    return TRUE;

}


BOOLEAN Recovering(HOOK_info* input_data) {
    // ���� API ȣ���� ���� ���� �۾�

    DWORD oldProtect;
    if (!VirtualProtect(input_data->Original_API_Address, input_data->Trampoline_HOOK_Code_Size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    // �����
    memcpy(
        input_data->Original_API_Address,
        input_data->Original_Code,
        input_data->Trampoline_HOOK_Code_Size
    );

    // �޸� ��ȣ ����
    VirtualProtect(input_data->Original_API_Address, input_data->Trampoline_HOOK_Code_Size, oldProtect, &oldProtect);

    return TRUE;
}



/////////
// ���Ḯ��Ʈ
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