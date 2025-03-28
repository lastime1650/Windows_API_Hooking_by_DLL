#include "pch.h"
#include "DynamicLength.h"



#include "Core_Server_Enum.h"
#include "Get_Time.h"

PUCHAR Make_Dynamic_Data_2_lengthbased(
	PLinkedListNode StartAddress,
	ULONG32* output_DynData_Size
) {

	Analysis_Command Cmd = API_HOOKING;

	// 길이 구하기
	ULONG32 SIZE =
		+ sizeof(Cmd) // 초기 명령어

		/*(4바이트 + 데이터길이 한 묶음)*/
		
		+ ( 4+ output_time_buffer_size)// 현재 시간
		+ (sizeof("_END") - 1) // 마감처리
	;

	// 4바이트 + 동적 길이데이터 길이 구하기

	PLinkedListNode Current = StartAddress;
	while (Current) {

		SIZE += 4;
		SIZE += Current->INPUT_DATA_SIZE;

		Current = (PLinkedListNode)Current->NextNode;
	}

	PUCHAR DynData = (PUCHAR)malloc(SIZE);
	memset(DynData, 0, SIZE);


	// 0. 인덱스가될 주소 변수정의
	PUCHAR current_address = DynData;

	// 1. Analysis 넣기
	memcpy(current_address, &Cmd, sizeof(Cmd));
	current_address += sizeof(Cmd);

	
	// 동적 데이터 넣기
	PLinkedListNode INPUT = StartAddress;
	while (INPUT) {

		//SIZE += 4;
		//SIZE += Current->INPUT_DATA_SIZE;
		memcpy(current_address, &INPUT->INPUT_DATA_SIZE, sizeof(INPUT->INPUT_DATA_SIZE));
		current_address += sizeof(INPUT->INPUT_DATA_SIZE);

		memcpy(current_address, INPUT->INPUT_DATA, INPUT->INPUT_DATA_SIZE);
		current_address += INPUT->INPUT_DATA_SIZE;

		INPUT = (PLinkedListNode)INPUT->NextNode;
	}


	//타임스탬프
	PCHAR Timestamp = GetTimeStamp();
	printf("현재시간 -> %s ", Timestamp);
	ULONG32 Timestamplen = Get_TimeStamp_BuffLen();
	memcpy(current_address, &Timestamplen, 4);
	current_address += 4;

	memcpy(current_address, Timestamp, Timestamplen);
	current_address += Timestamplen;

	FREE_GetTimeStamp(Timestamp);

	// 마감처리
	memcpy(current_address, "_END", sizeof("_END") - 1);

	return DynData;

}

VOID Free_Dynamic_Data_2_lengthbased(PUCHAR StartAddress) {
	free(StartAddress);
}