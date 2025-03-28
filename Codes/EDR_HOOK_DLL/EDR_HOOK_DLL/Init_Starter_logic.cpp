#include "pch.h"


#include "Init_Starter.h"

#include "API_list.h"
#include "Inline_hook.h"

BOOLEAN Init_Start() {
	BOOLEAN result = FALSE;

	// �ʱ�ȭ


	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");


	// API_list�� ���ڿ��� �ϳ��� �����ͼ� ntdll.dll �ּ� ã�� ���� ��ŷ �Լ��� ���� ��ŷ�ϱ�
	ULONG32 API_COUNT = sizeof(API_NAME_List[0]);
	for (ULONG32 index = 0; index < API_COUNT; index++) {
		//printf("index -> %d\n", index);
		// ��ŷ����
		PCHAR API_NAME = (PCHAR)malloc(sizeof(API_NAME_List[index]));
		memset(API_NAME, 0, sizeof(API_NAME_List[index]));

		memcpy(API_NAME, API_NAME_List[index], sizeof(API_NAME_List[index]));

		// ���� API�ּ� ��������
		PVOID Original_API_Address = (PVOID)GetProcAddress(
			hNtdll,
			API_NAME
		);

		if (!Original_API_Address)
			continue;

		//printf("��ŷ ���� ����@  ��ũ�� API�� -> %s\n", API_NAME);
		//printf("��ŷ ���� ����@  ���� �ּ� -> %p\n", Original_API_Address);

		if (Hooking(
			Original_API_Address,
			API_Hook_List[index],
			TRUE
		)) {
			//printf("��ŷ ����\n\n");
		}

	}


	// ntdll.dll ����

	return result;
}
