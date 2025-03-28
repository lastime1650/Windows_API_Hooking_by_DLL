#ifndef HOOK_
#define INLINE_HOOKING

#include <Windows.h>

typedef struct HOOK_info {

	// 레지스터에 주소를 저장하고 점프하는 방식

	// MOV RAX, HOOK_ADDRESS
	// JMP RAX
	CHAR Trampoline_HOOK_Code[12]; // 최대 사이즈 설정
	USHORT Trampoline_HOOK_Code_Size; // 실제 사용될 사이즈

	// 오리지널 후크 '전' 데이터
	CHAR Original_Code[12]; // 최대 사이즈 설정 ( 사이즈는 "Trampoline_HOOK_Code_Size" 멤버에 의존된다 ) 

	PVOID Original_API_Address;
	PVOID Hook_Address;

	HANDLE mutex_handle;

	PUCHAR Next_Node;
}HOOK_info, * PHOOK_info;

extern PHOOK_info Start_Hook_info_LIST_Address;
extern PHOOK_info Current_Hook_info_LIST_Address;

// 후킹
BOOLEAN Hooking(PVOID Original_API_Address, PVOID Hook_Address, BOOLEAN is_create_node);

// 후킹 복원
BOOLEAN Recovering(HOOK_info* input_data);

///

PHOOK_info Appending_info(PHOOK_info input);

PHOOK_info search_my_info(PVOID HOOK_ADDRESS);

#endif