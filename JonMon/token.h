#ifndef _TOKEN_
#define _TOKEN_
#include "shared.h"

NTSTATUS GetTokenUserName(HANDLE hToken, PUNICODE_STRING pFullName);

NTSTATUS GetUserTokenStatistics(HANDLE hToken, DWORD* AuthenticationId);

NTSTATUS GetProcessUserName(PUNICODE_STRING pFullName, HANDLE ProcessId, DWORD* AuthenticationId);

DWORD GetSessionIdFromToken(HANDLE hToken);

NTSTATUS GetImpersonationLevelFromToken(HANDLE hToken);

NTSTATUS GetTokenIntegrityLevel(HANDLE hToken, PUNICODE_STRING IntegrityLevel);

#endif // !_TOKEN_