#ifndef LINKEDLIST_H
#define LINK

#include <Windows.h>
#include <winternl.h>
#include <stdlib.h>


typedef struct LinkedListNode {

	PUCHAR INPUT_DATA;
	ULONG32 INPUT_DATA_SIZE;

	PUCHAR NextNode;

}LinkedListNode, * PLinkedListNode;

PLinkedListNode CreateListNode(PUCHAR INPUT_DATA, ULONG32 INPUT_DATA_SIZE, PCHAR nodename);
PLinkedListNode AppendListNode(PLinkedListNode current_node, PUCHAR INPUT_DATA, ULONG32 INPUT_DATA_SIZE, PCHAR nodename);

// +
PLinkedListNode AppendListNode_with_ACCESSMASK(PLinkedListNode current_node, ACCESS_MASK ACCESS_MASK_DATA); // ACCESS_MASK(DWORD) -> strcat

PLinkedListNode AppendListNode_with_UNICODE_STRING(PLinkedListNode current_node, PUNICODE_STRING unicode, PCHAR name); // UNICODE_STRING -> ANSI 

PLinkedListNode AppendListNode_with_NTSTATUS_2_STRING(PLinkedListNode current_node, NTSTATUS status); // NTSTATUS -> STRING

VOID RemoveAllNode(PLinkedListNode start_node);

#endif