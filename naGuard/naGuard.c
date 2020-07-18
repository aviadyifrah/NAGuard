/*++

Module Name:

    naGuard.c

Abstract:

    This is the main module of the naGuard miniFilter driver.

Environment:

    Kernel mode

--*/

#include "naGuard.h"
#include "Callbacks.h"
#include "Communication.h"



NAGUARD_DATA naGuardData;

//const WCHAR* honeypot_folder = L"0honeypot";
const WCHAR* extentions[] = { L"txt", L"xlsx", L"xls", L"pptx", L"ppt", L"docx", L"doc", L"zip", L"rar", L"mp3", L"mp4", L"mpg" ,L"png", L"gif", L"bmp", L"jpg", L"jpeg", L"ico" };
const int extentions_number = sizeof(extentions) / sizeof(WCHAR*);


NTSTATUS
naGuardInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();


    return STATUS_SUCCESS;
}


NTSTATUS
naGuardInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();


    return STATUS_SUCCESS;
}


VOID
naGuardInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

}


VOID
naGuardInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING portObjectNameString;

    NTSTATUS status = STATUS_SUCCESS;


    UNREFERENCED_PARAMETER( RegistryPath );

	try 
	{

		status = FltRegisterFilter( DriverObject, &FilterRegistration, &naGuardData.Filter );
		CHECK_STAUS_PRINT_ERROR(status, ("[NAGAURD] DriverEntry: FltRegisterFilter FAILED. status = 0x%x\n", status))
		
		//  Builds a default security descriptor for use with FltCreateCommunicationPort.
		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
		CHECK_STAUS_PRINT_ERROR(status, ("[NAGAURD] DriverEntry: FltBuildDefaultSecurityDescriptor FAILED. status = 0x%x\n", status))

		RtlInitUnicodeString(&portObjectNameString, NAGUARD_PORT_NAME);

		InitializeObjectAttributes(&oa, &portObjectNameString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

		status = FltCreateCommunicationPort(naGuardData.Filter, &naGuardData.ServerPort, &oa, NULL, naGuardConnect, naGuardDisconnect, naGuardMessage, 1);

		CHECK_STAUS_PRINT_ERROR(status, ("[NAGAURD] DriverEntry: FltCreateCommunicationPort FAILED. status = 0x%x\n", status))

		FltFreeSecurityDescriptor(sd);

		status = FltStartFiltering(naGuardData.Filter);

		CHECK_STAUS_PRINT_ERROR(status, ("[NAGAURD] DriverEntry: FltStartFiltering FAILED. status = 0x%x\n", status))

	} finally 
	{
		if (!NT_SUCCESS(status)) {

			if (NULL != naGuardData.ServerPort) {
				FltCloseCommunicationPort(naGuardData.ServerPort);
			}

			if (NULL != naGuardData.Filter) {
				FltUnregisterFilter(naGuardData.Filter);
			}
		}
	}

    return status;
}

NTSTATUS
naGuardUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	FltCloseCommunicationPort(naGuardData.ServerPort );

    FltUnregisterFilter( naGuardData.Filter );

    return STATUS_SUCCESS;
}


