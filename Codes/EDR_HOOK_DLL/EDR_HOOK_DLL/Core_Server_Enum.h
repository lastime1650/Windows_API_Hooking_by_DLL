#ifndef CORE_SERVER_ENUM

typedef enum Analysis_Command {

	/*
		����

		(1 xx xx ) : Ŀ�� -> �м�����
		( 2 xx xx ) : �м����� -> Ŀ��

		ù��° �ڸ� : ��ɾ��� ����
		�ι�° �ڸ� : ����
		����° �ڸ� : ����

	*/

	// Ŀ�� -> �м����� ( 1 xx xx )
	//PsSetCreateProcessNotifyRoutine_Creation = 10101,
	//PsSetCreateProcessNotifyRoutine_Remove = 10102,
	//PsSetCreateProcessNotifyRoutine_Creation_Detail = 10103,

	//PsSetCreateThreadNotifyRoutine_Creation = 10201,
	//PsSetCreateThreadNotifyRoutine_Remove = 10202,

	//PsSetLoadImageNotifyRoutine_Load = 10301,

	//CmRegisterCallbackEx_for_mon = 10401,

	// ��Ʈ��ũ Ȱ�� NDIS
	//NDIS_Network_Traffic = 10501,

	// ���� �ý��� Ȱ��
	//File_System = 10601,

	// ����
	//Response_Process = 10710,
	//Response_Process_Remove = 10711,

	//Response_Network = 10720,
	//Response_Network_Remove = 10721,

	//Response_File = 10730,
	//Response_File_Remove = 10731,
	//get_Response_list = 10799, // ���� ���� ��ϵ� �͵� ��� ��������

	// + API ��ŷ
	API_HOOKING = 10800, // API��ŷ����

	// �м����� -> Ŀ�� ( 2 xx xx )
	//Request_ALL_Monitored_Data = 20101,
	//Request_Real_File = 20201,
	//Running_Process_list = 20301, // ���� �������� ���μ��� ��� ����
	//Request_PID_info = 20401, // PID_ to Detail


	// ���� ( 9 xx xx )
	SUCCESS = 90001,
	FAIL = 90002
}Analysis_Command;

#endif

