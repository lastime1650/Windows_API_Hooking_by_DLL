#ifndef HOOK_
#define INLINE_HOOKING

#include <Windows.h>

typedef struct HOOK_info {

	// �������Ϳ� �ּҸ� �����ϰ� �����ϴ� ���

	// MOV RAX, HOOK_ADDRESS
	// JMP RAX
	CHAR Trampoline_HOOK_Code[12]; // �ִ� ������ ����
	USHORT Trampoline_HOOK_Code_Size; // ���� ���� ������

	// �������� ��ũ '��' ������
	CHAR Original_Code[12]; // �ִ� ������ ���� ( ������� "Trampoline_HOOK_Code_Size" ����� �����ȴ� ) 

	PVOID Original_API_Address;
	PVOID Hook_Address;

	HANDLE mutex_handle;

	PUCHAR Next_Node;
}HOOK_info, * PHOOK_info;

extern PHOOK_info Start_Hook_info_LIST_Address;
extern PHOOK_info Current_Hook_info_LIST_Address;

// ��ŷ
BOOLEAN Hooking(PVOID Original_API_Address, PVOID Hook_Address, BOOLEAN is_create_node);

// ��ŷ ����
BOOLEAN Recovering(HOOK_info* input_data);

///

PHOOK_info Appending_info(PHOOK_info input);

PHOOK_info search_my_info(PVOID HOOK_ADDRESS);

#endif