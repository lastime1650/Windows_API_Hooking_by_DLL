#include "pch.h"


#include "Init_Starter.h"

#include "API_list.h"
#include "Inline_hook.h"

BOOLEAN Init_Start() {
	BOOLEAN result = FALSE;

	// 초기화


	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");


	// API_list의 문자열을 하나씩 가져와서 ntdll.dll 주소 찾은 다음 후킹 함수를 통해 후킹하기
	ULONG32 API_COUNT = sizeof(API_NAME_List[0]);
	for (ULONG32 index = 0; index < API_COUNT; index++) {
		//printf("index -> %d\n", index);
		// 후킹시작
		PCHAR API_NAME = (PCHAR)malloc(sizeof(API_NAME_List[index]));
		memset(API_NAME, 0, sizeof(API_NAME_List[index]));

		memcpy(API_NAME, API_NAME_List[index], sizeof(API_NAME_List[index]));

		// 실제 API주소 가져오기
		PVOID Original_API_Address = (PVOID)GetProcAddress(
			hNtdll,
			API_NAME
		);

		if (!Original_API_Address)
			continue;

		//printf("후킹 시작 직전@  후크할 API명 -> %s\n", API_NAME);
		//printf("후킹 시작 직전@  실제 주소 -> %p\n", Original_API_Address);

		if (Hooking(
			Original_API_Address,
			API_Hook_List[index],
			TRUE
		)) {
			//printf("후킹 성공\n\n");
		}

	}


	// ntdll.dll 전용

	return result;
}
