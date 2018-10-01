#include "Callbacks.h"
#include <math.h>

extern NAGUARD_DATA naGuardData;
extern const WCHAR* extentions;
extern const int extentions_number;

/*
#ifdef __cplusplus
extern "C" {
#endif
	int _fltused = 0;
#ifdef __cplusplus
}
#endif
*/

/*************************************************************************
Aux functions.
*************************************************************************/
float calculateEntropy(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects, USHORT SectorSize)
{
	PAGED_CODE();
	NTSTATUS status;

	LARGE_INTEGER offset;
	ULONG bytesRead = 0;
	offset.QuadPart = bytesRead = 0;

	

	ULONG file_size = max(SectorSize, Data->Iopb->TargetFileObject->Size);

	unsigned char *buffer = (unsigned char*)FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, file_size, 'teaN');
	if (buffer == NULL)
		return 0;

	status = FltReadFile(FltObjects->Instance, FltObjects->FileObject, &offset,
		file_size, buffer,
		FLTFL_IO_OPERATION_NON_CACHED |
		FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
		&bytesRead,
		NULL,
		NULL);


	float entropy = 0;
	ULONG i;
	unsigned char tmp = 0;
	float p = 0;
	ULONG hist[256] = { 0 };
	

	for (i = 0; i < bytesRead; i++) {
		tmp = buffer[i];
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "tmp: %u\n", tmp);
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "hist[tmp]: %d\n", hist[tmp]);
		hist[tmp]++;
	}

	
	for (i = 0; i < 256; i++) {
		p = (float)(hist[i]) / (float)(file_size);
		if (p > 0)
			entropy = entropy - p * logf(p);
	}

		


	FltFreePoolAlignedWithTag(FltObjects->Instance, buffer, 'teaN');

	return entropy;
}


/*************************************************************************
MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
naGuardPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPreOperation\n");
	NTSTATUS status;
	//LARGE_INTEGER offset;
	//ULONG bytesRead;
	ULONG length;
	FLT_VOLUME_PROPERTIES volumeProps;
	PFLT_VOLUME volume = NULL;

	
	//UNREFERENCED_PARAMETER(status);
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);

	status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
	status = FltGetVolumeProperties(volume, &volumeProps, sizeof(volumeProps), &length);

	//Alocate message
	PNAGUARD_FMESSAGE msg = ExAllocatePoolWithTag(NonPagedPool, sizeof(NAGUARD_FMESSAGE), 'tfaN');

	msg->process_id = PsGetCurrentProcessId();
	msg->preop_entropy = 0;
	msg->postop_entropy = 0;

	//Write Operation
	if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
		msg->opcode = IRP_MJ_CREATE;
	}
	else if (Data->Iopb->MajorFunction == IRP_MJ_WRITE){
		msg->opcode = IRP_MJ_WRITE;
	}
	else if (Data->Iopb->MajorFunction == IRP_MJ_READ){
		msg->opcode = IRP_MJ_READ;
	}
	else if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
		msg->opcode = IRP_MJ_SET_INFORMATION;
	}
	else {
		msg->opcode = -1;
	}

	
	//if (Data->Iopb->TargetFileObject->FileObjectExtension)
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard! Data->Iopb->TargetFileObject->FileName.Buffer %S\n", Data->Iopb->TargetFileObject->FileName.Buffer);
	PFLT_FILE_NAME_INFORMATION  nameInfo;
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	if (status == STATUS_SUCCESS) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard! in if\n");
		FltParseFileNameInformation(nameInfo);
		for (int i = 0; i < extentions_number; i++){
			if (nameInfo->Extension.Length != 0 && wcscmp(nameInfo->Extension.Buffer, &extentions[i]) == 0 ) {
				RtlZeroMemory(msg->preop_filename, 4096);
				RtlCopyMemory(msg->preop_filename, nameInfo->Name.Buffer, min(4096, nameInfo->Name.Length) );
				msg->preop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
				*CompletionContext = msg;
				return FLT_PREOP_SUCCESS_WITH_CALLBACK;
			}
		}
	}


	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard! Failed for Data->Iopb->TargetFileObject->FileName.Buffer %S, status: %u, OPCODE: %d\n", 
		Data->Iopb->TargetFileObject->FileName.Buffer, status, Data->Iopb->MajorFunction);
	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



FLT_POSTOP_CALLBACK_STATUS
naGuardPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPostOperation\n");
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS status;
	//LARGE_INTEGER offset;
	//ULONG bytesRead;
	//PVOID buffer = NULL;
	ULONG length;
	FLT_VOLUME_PROPERTIES volumeProps;
	PFLT_VOLUME volume = NULL;
	PNAGUARD_FMESSAGE msg = (PNAGUARD_FMESSAGE)CompletionContext;

	status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
	status = FltGetVolumeProperties(volume, &volumeProps, sizeof(volumeProps), &length);


	PFLT_FILE_NAME_INFORMATION  nameInfo;
	LARGE_INTEGER timeout;
	timeout.QuadPart = 100000;
	 
	if (FltObjects->FileObject != NULL && STATUS_SUCCESS == FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) {
		FltParseFileNameInformation(nameInfo);
		RtlZeroMemory(msg->postop_filename, 4096);
		RtlCopyMemory(msg->postop_filename, Data->Iopb->TargetFileObject->FileName.Buffer , min(4096, Data->Iopb->TargetFileObject->FileName.Length));
		msg->postop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
		if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
			msg->opcode = 5;
		}
		FltSendMessage(naGuardData.Filter, &naGuardData.ClientPort, msg, sizeof(NAGUARD_FMESSAGE), NULL, 0, &timeout);
	}
	



	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_POSTOP_FINISHED_PROCESSING;
}








FLT_PREOP_CALLBACK_STATUS
naGuardPreSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPreOperation\n");
	NTSTATUS status;
	//LARGE_INTEGER offset;
	//ULONG bytesRead;
	ULONG length;
	FLT_VOLUME_PROPERTIES volumeProps;
	PFLT_VOLUME volume = NULL;

	
	//UNREFERENCED_PARAMETER(status);
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);

	FILE_INFORMATION_CLASS fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

	status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
	status = FltGetVolumeProperties(volume, &volumeProps, sizeof(volumeProps), &length);

	//Alocate message
	PNAGUARD_FMESSAGE msg = ExAllocatePoolWithTag(NonPagedPool, sizeof(NAGUARD_FMESSAGE), 'tfaN');

	msg->process_id = PsGetCurrentProcessId();
	msg->preop_entropy = 0;
	msg->postop_entropy = 0;
	

	//if (Data->Iopb->TargetFileObject->FileObjectExtension)
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard! Data->Iopb->TargetFileObject->FileName.Buffer %S\n", Data->Iopb->TargetFileObject->FileName.Buffer);
	PFLT_FILE_NAME_INFORMATION  nameInfo;
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	if (fileInfoClass == FileRenameInformation && status == STATUS_SUCCESS) {
		FltParseFileNameInformation(nameInfo);
		if (nameInfo->Extension.Length != 0) {
			RtlZeroMemory(msg->preop_filename, 4096);
			RtlCopyMemory(msg->preop_filename, nameInfo->Name.Buffer, min(4096, nameInfo->Name.Length));
			msg->preop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
			msg->opcode = 2;
			*CompletionContext = msg;
			return FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}
	}
	else if ((fileInfoClass == FileDispositionInformation || fileInfoClass == FileDispositionInformationEx) && status == STATUS_SUCCESS) {
		FltParseFileNameInformation(nameInfo);
		if (nameInfo->Extension.Length != 0) {
			RtlZeroMemory(msg->preop_filename, 4096);
			RtlCopyMemory(msg->preop_filename, nameInfo->Name.Buffer, min(4096, nameInfo->Name.Length));
			msg->preop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
			msg->opcode = 3;
			*CompletionContext = msg;
			return FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}
	}

	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



FLT_POSTOP_CALLBACK_STATUS
naGuardPostSetInformation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPostOperation\n");
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS status;
	//LARGE_INTEGER offset;
	//ULONG bytesRead;
	//PVOID buffer = NULL;
	ULONG length;
	FLT_VOLUME_PROPERTIES volumeProps;
	PFLT_VOLUME volume = NULL;
	PNAGUARD_FMESSAGE msg = (PNAGUARD_FMESSAGE)CompletionContext;

	status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
	status = FltGetVolumeProperties(volume, &volumeProps, sizeof(volumeProps), &length);

	PFLT_FILE_NAME_INFORMATION  nameInfo;
	LARGE_INTEGER timeout;
	timeout.QuadPart = 100000;
	if (STATUS_SUCCESS == FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) {
		FltParseFileNameInformation(nameInfo);
		RtlZeroMemory(msg->postop_filename, 4096);
		RtlCopyMemory(msg->postop_filename, nameInfo->Name.Buffer, min(4096, nameInfo->Name.Length));
		msg->postop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
		FltSendMessage(naGuardData.Filter, &naGuardData.ClientPort, msg, sizeof(NAGUARD_FMESSAGE), NULL, 0, &timeout);
	}




	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_POSTOP_FINISHED_PROCESSING;
}




FLT_PREOP_CALLBACK_STATUS
naGuardPreCleanup(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPreOperation\n");
	NTSTATUS status;
	//LARGE_INTEGER offset;
	//ULONG bytesRead;
	ULONG length;
	FLT_VOLUME_PROPERTIES volumeProps;
	PFLT_VOLUME volume = NULL;


	//UNREFERENCED_PARAMETER(status);
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);

	FILE_INFORMATION_CLASS fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

	if (fileInfoClass == FileDispositionInformationEx) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!FileDispositionInformationEx\n");
	}

	status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
	status = FltGetVolumeProperties(volume, &volumeProps, sizeof(volumeProps), &length);

	//Alocate message
	PNAGUARD_FMESSAGE msg = ExAllocatePoolWithTag(NonPagedPool, sizeof(NAGUARD_FMESSAGE), 'tfaN');

	msg->process_id = PsGetCurrentProcessId();
	msg->preop_entropy = 0;
	msg->postop_entropy = 0;


	//if (Data->Iopb->TargetFileObject->FileObjectExtension)
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard! Data->Iopb->TargetFileObject->FileName.Buffer %S\n", Data->Iopb->TargetFileObject->FileName.Buffer);
	PFLT_FILE_NAME_INFORMATION  nameInfo;
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	FltParseFileNameInformation(nameInfo);
	if (nameInfo->Extension.Length != 0 && fileInfoClass != 0) {
		if (fileInfoClass == FileDispositionInformation && status == STATUS_SUCCESS) {
			FltParseFileNameInformation(nameInfo);
			if (nameInfo->Extension.Length != 0) {
				RtlZeroMemory(msg->preop_filename, 4096);
				RtlCopyMemory(msg->preop_filename, nameInfo->Name.Buffer, min(4096, nameInfo->Name.Length));
				msg->preop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
				msg->opcode = 3;
				*CompletionContext = msg;
				return FLT_PREOP_SUCCESS_WITH_CALLBACK;
			}
		}
	}
	

	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



FLT_POSTOP_CALLBACK_STATUS
naGuardPostCleanup(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPostCleanup\n");
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	PNAGUARD_FMESSAGE msg = (PNAGUARD_FMESSAGE)CompletionContext;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPostCleanup: %S\n", msg->preop_filename);


	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_POSTOP_FINISHED_PROCESSING;
}







FLT_PREOP_CALLBACK_STATUS
naGuardPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPreOperation\n");
	NTSTATUS status;
	//LARGE_INTEGER offset;
	//ULONG bytesRead;
	ULONG length;
	FLT_VOLUME_PROPERTIES volumeProps;
	PFLT_VOLUME volume = NULL;


	//UNREFERENCED_PARAMETER(status);
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);

	//FILE_INFORMATION_CLASS fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

	status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
	status = FltGetVolumeProperties(volume, &volumeProps, sizeof(volumeProps), &length);

	//Alocate message
	PNAGUARD_FMESSAGE msg = ExAllocatePoolWithTag(NonPagedPool, sizeof(NAGUARD_FMESSAGE), 'tfaN');

	msg->process_id = PsGetCurrentProcessId();
	msg->preop_entropy = 0;
	msg->postop_entropy = 0;


	PFLT_FILE_NAME_INFORMATION  nameInfo;
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
		FltParseFileNameInformation(nameInfo);
		if (nameInfo->Extension.Length != 0) {
			RtlZeroMemory(msg->preop_filename, 4096);
			RtlCopyMemory(msg->preop_filename, nameInfo->Name.Buffer, min(4096, nameInfo->Name.Length));
			msg->preop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
			msg->opcode = 4;
			*CompletionContext = msg;
			return FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}
	}

	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



FLT_POSTOP_CALLBACK_STATUS
naGuardPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPostOperation\n");
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS status;
	//LARGE_INTEGER offset;
	//ULONG bytesRead;
	//PVOID buffer = NULL;
	ULONG length;
	FLT_VOLUME_PROPERTIES volumeProps;
	PFLT_VOLUME volume = NULL;
	PNAGUARD_FMESSAGE msg = (PNAGUARD_FMESSAGE)CompletionContext;

	status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
	status = FltGetVolumeProperties(volume, &volumeProps, sizeof(volumeProps), &length);

	PFLT_FILE_NAME_INFORMATION  nameInfo;
	LARGE_INTEGER timeout;
	timeout.QuadPart = 100000;
	if (STATUS_SUCCESS == FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) {
		FltParseFileNameInformation(nameInfo);
		RtlZeroMemory(msg->postop_filename, 4096);
		RtlCopyMemory(msg->postop_filename, nameInfo->Name.Buffer, min(4096, nameInfo->Name.Length));
		msg->postop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
		FltSendMessage(naGuardData.Filter, &naGuardData.ClientPort, msg, sizeof(NAGUARD_FMESSAGE), NULL, 0, &timeout);
	}




	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_POSTOP_FINISHED_PROCESSING;
}







FLT_PREOP_CALLBACK_STATUS
naGuardPreWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPreOperation\n");
	NTSTATUS status;
	//LARGE_INTEGER offset;
	//ULONG bytesRead;
	ULONG length;
	FLT_VOLUME_PROPERTIES volumeProps;
	PFLT_VOLUME volume = NULL;


	//UNREFERENCED_PARAMETER(status);
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);

	//FILE_INFORMATION_CLASS fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

	status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
	status = FltGetVolumeProperties(volume, &volumeProps, sizeof(volumeProps), &length);

	//Alocate message
	PNAGUARD_FMESSAGE msg = ExAllocatePoolWithTag(NonPagedPool, sizeof(NAGUARD_FMESSAGE), 'tfaN');

	msg->process_id = PsGetCurrentProcessId();
	msg->preop_entropy = 0;
	msg->postop_entropy = 0;


	PFLT_FILE_NAME_INFORMATION  nameInfo;
	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	if (status == STATUS_SUCCESS) {
		FltParseFileNameInformation(nameInfo);
		if (nameInfo->Extension.Length != 0) {
			RtlZeroMemory(msg->preop_filename, 4096);
			RtlCopyMemory(msg->preop_filename, nameInfo->Name.Buffer, min(4096, nameInfo->Name.Length));
			msg->preop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
			msg->opcode = 1;
			*CompletionContext = msg;
			return FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}
	}
	
	

	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



FLT_POSTOP_CALLBACK_STATUS
naGuardPostWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "naGuard!naGuardPostOperation\n");
	//UNREFERENCED_PARAMETER(Data);
	//UNREFERENCED_PARAMETER(FltObjects);
	//UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS status;
	//LARGE_INTEGER offset;
	//ULONG bytesRead;
	//PVOID buffer = NULL;
	ULONG length;
	FLT_VOLUME_PROPERTIES volumeProps;
	PFLT_VOLUME volume = NULL;
	PNAGUARD_FMESSAGE msg = (PNAGUARD_FMESSAGE)CompletionContext;

	status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
	status = FltGetVolumeProperties(volume, &volumeProps, sizeof(volumeProps), &length);

	PFLT_FILE_NAME_INFORMATION  nameInfo;
	LARGE_INTEGER timeout;
	timeout.QuadPart = 100000;
	if (STATUS_SUCCESS == FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)) {
		FltParseFileNameInformation(nameInfo);
		RtlZeroMemory(msg->postop_filename, 4096);
		RtlCopyMemory(msg->postop_filename, nameInfo->Name.Buffer, min(4096, nameInfo->Name.Length));
		msg->postop_entropy = calculateEntropy(Data, FltObjects, volumeProps.SectorSize);
		FltSendMessage(naGuardData.Filter, &naGuardData.ClientPort, msg, sizeof(NAGUARD_FMESSAGE), NULL, 0, &timeout);
	}




	ExFreePoolWithTag(msg, 'tfaN');
	return FLT_POSTOP_FINISHED_PROCESSING;
}






















VOID
naGuardOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(ParameterSnapshot);
	UNREFERENCED_PARAMETER(OperationStatus);
	UNREFERENCED_PARAMETER(RequesterContext);
}


FLT_PREOP_CALLBACK_STATUS
naGuardPreOperationNoPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);


	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
naGuardDoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//
	//  return boolean state based on which operations we are interested in
	//

	return (BOOLEAN)

		//
		//  Check for oplock operations
		//

		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
		((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

			||

			//
			//    Check for directy change notification
			//

			((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
			(iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
			);
}
