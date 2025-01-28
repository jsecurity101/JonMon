#pragma once
#include <TraceLoggingProvider.h> 

#define JonMon_DEVICE 0x8010

#define IOCTL_CHANGE_PROTECTION_LEVEL_PROCESS CTL_CODE(JonMon_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EVENT_CONFIGURATION CTL_CODE(JonMon_DEVICE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)


VOID WINAPI ServiceCtrlHandler(
	_In_ DWORD dwCtrl
);

VOID WINAPI ServiceMain(
	_In_ DWORD argc, 
	_In_ LPTSTR* argv
);

DWORD CreateCustomService(
	_In_ LPCWSTR ServiceName, 
	_In_ LPCWSTR ImagePath, 
	_In_ DWORD dwServiceType
);

DWORD StartCustomService(
	_In_ LPCWSTR ServiceName
);

DWORD StopCustomService(
	_In_ LPCWSTR ServiceName
);

DWORD DeleteCustomService(
	_In_ LPCWSTR ServiceName
);

DWORD UninstallManifest();

DWORD InstallManifest();

VOID ChangePPL();

DWORD ProtectionCheck();

VOID LoadExtensions();





