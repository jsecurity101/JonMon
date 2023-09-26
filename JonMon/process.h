#ifndef _PROCESS_
#define _PROCESS_
#include "shared.h"

typedef NTSTATUS(*ZWQUERYINFORMATIONPROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);


NTSTATUS GetProcessImageName(HANDLE processId, PUNICODE_STRING ProcessImageName);
NTSTATUS GetProcessToken(HANDLE processId, PHANDLE hToken);

#endif // !_PROCESS_
