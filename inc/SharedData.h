#ifndef __SHAREDDATA_H__
#define __SHAREDDATA_H__

#define NAGUARD_PORT_NAME                   L"\\naGuardPort"

typedef struct filter_message_t {
	int	opcode;
	HANDLE process_id;
	float preop_entropy;
	float postop_entropy;
	WCHAR preop_filename[4096];
	WCHAR postop_filename[4096];

} NAGUARD_FMESSAGE, *PNAGUARD_FMESSAGE;

typedef struct message_user_t {
	HANDLE process_id;
} NAGUARD_UMESSAGE, *PNAGUARD_UMESSAGE;

#endif
