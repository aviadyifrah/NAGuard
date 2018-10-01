#include "naGuard.h"


//---------------------------------------------------------------------------
//  Registration information for FLTMGR.
//---------------------------------------------------------------------------


CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	
	/* Handle delete op*/
	{ IRP_MJ_CREATE,
	0,
	naGuardPreCreate,
	naGuardPostCreate },

	/*
	{ IRP_MJ_READ,
	0,
	naGuardPreOperation,
	naGuardPostOperation },
	*/

	{ IRP_MJ_WRITE,
	0,
	naGuardPreWrite,
	naGuardPostWrite },


	/* Handle rename, delete op*/
	{ IRP_MJ_SET_INFORMATION,
	0,
	naGuardPreSetInformation,
	naGuardPostSetInformation },

	/*
	{ IRP_MJ_CLEANUP,
	0,
	naGuardPreCleanup,
	naGuardPostCleanup },
	*/

	{ IRP_MJ_OPERATION_END }
};


CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks

	naGuardUnload,                           //  MiniFilterUnload

	naGuardInstanceSetup,                    //  InstanceSetup
	naGuardInstanceQueryTeardown,            //  InstanceQueryTeardown
	naGuardInstanceTeardownStart,            //  InstanceTeardownStart
	naGuardInstanceTeardownComplete,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};
