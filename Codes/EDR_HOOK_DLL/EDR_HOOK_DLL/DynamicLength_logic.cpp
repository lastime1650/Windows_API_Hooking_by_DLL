#include "pch.h"
#include "DynamicLength.h"



#include "Core_Server_Enum.h"
#include "Get_Time.h"

PUCHAR Make_Dynamic_Data_2_lengthbased(
	PLinkedListNode StartAddress,
	ULONG32* output_DynData_Size
) {

	Analysis_Command Cmd = API_HOOKING;

	// ���� ���ϱ�
	ULONG32 SIZE =
		+ sizeof(Cmd) // �ʱ� ��ɾ�

		/*(4����Ʈ + �����ͱ��� �� ����)*/
		
		+ ( 4+ output_time_buffer_size)// ���� �ð�
		+ (sizeof("_END") - 1) // ����ó��
	;

	// 4����Ʈ + ���� ���̵����� ���� ���ϱ�

	PLinkedListNode Current = StartAddress;
	while (Current) {

		SIZE += 4;
		SIZE += Current->INPUT_DATA_SIZE;

		Current = (PLinkedListNode)Current->NextNode;
	}

	PUCHAR DynData = (PUCHAR)malloc(SIZE);
	memset(DynData, 0, SIZE);


	// 0. �ε������� �ּ� ��������
	PUCHAR current_address = DynData;

	// 1. Analysis �ֱ�
	memcpy(current_address, &Cmd, sizeof(Cmd));
	current_address += sizeof(Cmd);

	
	// ���� ������ �ֱ�
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


	//Ÿ�ӽ�����
	PCHAR Timestamp = GetTimeStamp();
	printf("����ð� -> %s ", Timestamp);
	ULONG32 Timestamplen = Get_TimeStamp_BuffLen();
	memcpy(current_address, &Timestamplen, 4);
	current_address += 4;

	memcpy(current_address, Timestamp, Timestamplen);
	current_address += Timestamplen;

	FREE_GetTimeStamp(Timestamp);

	// ����ó��
	memcpy(current_address, "_END", sizeof("_END") - 1);

	return DynData;

}

VOID Free_Dynamic_Data_2_lengthbased(PUCHAR StartAddress) {
	free(StartAddress);
}