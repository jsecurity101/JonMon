#ifndef _THREAD_
#define _THREAD_
#include "shared.h"

//
// Grabbed from: https://github.com/zodiacon/SystemExplorer/blob/f5d51f63581807dbd2a8957bc4bc9dae4aa001cc/KObjExp/KObjExp.cpp#L15
//
extern "C" NTSTATUS ZwOpenThread(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId);


NTSTATUS GetThreadHandle(CLIENT_ID ThreadId, PHANDLE hToken);

// Define the process object and thread object structures
VOID GetThreadToken(HANDLE hThread);

NTSTATUS GetThreadImpersonationLevel(PETHREAD thread, PSECURITY_IMPERSONATION_LEVEL ImpersonationLevel, PUNICODE_STRING ImpersonationName);

NTSTATUS ThreadImpersonationEvent(HANDLE hToken, PETHREAD eThread, PCWSTR OperationType, WCHAR* RequestorImagePath, ULONGLONG USourceProcessId, ULONGLONG sourceProcStartKey, ULONGLONG UTargetProcessId, ULONGLONG targetProcStartkey);

#endif // !_THREAD_