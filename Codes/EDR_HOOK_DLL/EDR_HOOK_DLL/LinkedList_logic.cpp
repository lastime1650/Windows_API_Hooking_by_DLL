#include "pch.h"
#include "LinkedList.h"


PLinkedListNode CreateListNode(PUCHAR INPUT_DATA, ULONG32 INPUT_DATA_SIZE, PCHAR nodename) {


	/*&

		한 데이터를 전달할 때, 그 데이터의 의미를 포함해야하므로
		1 Data -> 2 node 로 부담된다.

		[0]node : Ansi 문자열 ( JSON에서 실제 데이터의 key 값이라고 생각하라 ) -- Key
		[1]node : 실제 데이터가 들어감  -- Value

		이런 형태로 구현되어야한다.

	*/


	// [0]node 생성
	PLinkedListNode _0_node = (PLinkedListNode)malloc(sizeof(LinkedListNode));

	if (!_0_node)
		return NULL;

	memset(_0_node, 0, sizeof(LinkedListNode));

	///

	_0_node->INPUT_DATA_SIZE = (ULONG32)strlen(nodename);
	_0_node->INPUT_DATA = (PUCHAR)malloc(strlen(nodename)); // null 미포함
	memcpy(_0_node->INPUT_DATA, nodename, strlen(nodename));




	// [1]node 생성

	PLinkedListNode _1_node = (PLinkedListNode)malloc(sizeof(LinkedListNode));

	if (!_1_node)
		return NULL;
	memset(_1_node, 0, sizeof(LinkedListNode));

	// [0]node(NextNode) -> [1]node 연결하기
	_0_node->NextNode = (PUCHAR)_1_node;

	///

	_1_node->INPUT_DATA_SIZE = INPUT_DATA_SIZE;
	_1_node->INPUT_DATA = (PUCHAR)malloc(INPUT_DATA_SIZE);
	memcpy(_1_node->INPUT_DATA, INPUT_DATA, INPUT_DATA_SIZE);

	_1_node->NextNode = NULL;

	///

	return _1_node;
}

PLinkedListNode AppendListNode(PLinkedListNode current_node, PUCHAR INPUT_DATA, ULONG32 INPUT_DATA_SIZE, PCHAR nodename) {



	if (current_node) {
		PLinkedListNode NEW_NODE = CreateListNode(INPUT_DATA, INPUT_DATA_SIZE, nodename);
		current_node->NextNode = (PUCHAR)NEW_NODE;

		return NEW_NODE;
	}
	else {
		return NULL;
	}

}

// ACCESS_MASK 전용
#include "ACCESS_MASK_to_str_.h"
PLinkedListNode AppendListNode_with_ACCESSMASK(PLinkedListNode current_node, ACCESS_MASK ACCESS_MASK_DATA) {



	if (current_node) {

		// 권한해석->문자열 변환
		ULONG32 AccessMask_StringA_strlen = 0;
		PCHAR AccessMask_StringA = AccessMaskToString((DWORD)ACCESS_MASK_DATA, &AccessMask_StringA_strlen);


		PLinkedListNode NEW_NODE = CreateListNode((PUCHAR)AccessMask_StringA, AccessMask_StringA_strlen + 1, (PCHAR)"ACCESS_MASK:");
		current_node->NextNode = (PUCHAR)NEW_NODE;

		// 해제
		FREE_AccessMaskToString(AccessMask_StringA);

		return NEW_NODE;
	}
	else {
		return NULL;
	}

}

// UNICODE 전용
PLinkedListNode AppendListNode_with_UNICODE_STRING(PLinkedListNode current_node, PUNICODE_STRING unicode, PCHAR name) {



	if (current_node) {

		// UNICODE_STRING -> ANSI_STRING 변환
		ANSI_STRING ansi = { 0 };
		RtlUnicodeStringToAnsiString(&ansi, (PCUNICODE_STRING)unicode, TRUE);


		PLinkedListNode NEW_NODE = CreateListNode((PUCHAR)ansi.Buffer, ansi.Length, name);
		current_node->NextNode = (PUCHAR)NEW_NODE;

		// 해제
		RtlFreeAnsiString(&ansi);

		return NEW_NODE;
	}
	else {
		return NULL;
	}

}

// NTSTATUS 전용
#include "NTSTATUS_2_STRING.h"
PLinkedListNode AppendListNode_with_NTSTATUS_2_STRING(PLinkedListNode current_node, NTSTATUS status) {



	if (current_node) {

		// NTSTATUS -> A STRING 변환
		ULONG32 ntstatus_string_size = 0;
		PCHAR ntstatus_string = NTSTATUS_2_STRING(status, &ntstatus_string_size);


		PLinkedListNode NEW_NODE = CreateListNode((PUCHAR)ntstatus_string, ntstatus_string_size, (PCHAR)"NTSTATUS:");
		current_node->NextNode = (PUCHAR)NEW_NODE;

		// 해제
		FREE_NTSTATUS_2_STRING(ntstatus_string);

		return NEW_NODE;
	}
	else {
		return NULL;
	}

}

VOID RemoveAllNode(PLinkedListNode start_node) {

	PLinkedListNode current = start_node;

	while (current) {
		PLinkedListNode remember_next_node = (PLinkedListNode)current->NextNode;

		free(current->INPUT_DATA); // INPUT_DATA 할당해제

		free(current);


		current = remember_next_node;
	}

	return;
}