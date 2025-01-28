#pragma once
#include <evntcons.h>
#include "tlhelp32.h"
#include <iostream>
#include <vector>
#pragma comment(lib, "tdh.lib")



typedef struct _TokenInformation {
	std::wstring userName;
	DWORD tokenType;
	LUID authenticationId;
	LUID linkedAuthenticationId;
	std::wstring integrityLevel;
	DWORD sessionId;
} TokenInformation, * PTokenInformation;

typedef struct _ProcessInformation {
	DWORD processId;
	std::wstring processName;
	std::wstring userName;
	DWORD tokenType;
	LUID authenticationId;
	LUID linkedAuthenticationId;
	std::wstring integrityLevel;
	DWORD sessionId;
} ProcessInformation, * PProcessInformation;

// 
// global variables that hold process ids and process names of every process currently running
//
extern std::vector<ProcessInformation> processList;

extern std::vector<ProcessInformation> initialProcessList;


DWORD GetUserInformation(
	_In_ DWORD processId, 
	_In_ PTokenInformation tokenInformation
);

DWORD GetMandatoryLabel(
	_In_ HANDLE hToken,
	_In_ std::wstring& integrityLevel
);

DWORD GetAuthenticationId(
	_In_ HANDLE hToken,
	_In_ PLUID authId
);

DWORD GetTokenUserInfo(
	_In_ HANDLE hToken,
	_In_ std::wstring& fullUserName
);

void UpdateProcessListPeriodically();

void ClearListPeriodically();

PProcessInformation GetProcessName(
	_In_ DWORD processId
);

void InitialProcesses();
