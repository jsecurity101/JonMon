#pragma once
#include <evntcons.h>

int GetTokenUser(
	_In_ DWORD ProcessId, 
	_Out_ wchar_t** Username
);

int GetImagePath(
	_In_ DWORD ProcessId, 
	_Out_ wchar_t** ImagePath
);