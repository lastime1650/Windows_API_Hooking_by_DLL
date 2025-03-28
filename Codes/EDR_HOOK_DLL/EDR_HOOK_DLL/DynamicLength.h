#ifndef DYNAMIC_LENGTH_H


#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "LinkedList.h"

PUCHAR Make_Dynamic_Data_2_lengthbased(
	PLinkedListNode StartAddress,
	ULONG32* output_DynData_Size
);


VOID Free_Dynamic_Data_2_lengthbased(PUCHAR StartAddress);
#endif