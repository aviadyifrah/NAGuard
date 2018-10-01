
#include "naGuard.h"

/*
Opcodes:
	 0 - Read
	 1 - Write
	 2 - Rename
	 3 - Delete
*/


/*************************************************************************
Prototypes
*************************************************************************/

EXTERN_C_START

NTSTATUS
naGuardConnect(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
);

VOID
naGuardDisconnect(
	_In_opt_ PVOID ConnectionCookie
);

NTSTATUS
naGuardMessage(
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferLength
);

EXTERN_C_END


#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, naGuardConnect)
#pragma alloc_text(PAGE, naGuardDisconnect)
#pragma alloc_text(PAGE, naGuardMessage)

#endif



