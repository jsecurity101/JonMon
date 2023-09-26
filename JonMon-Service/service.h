#pragma once

VOID WINAPI ServiceCtrlHandler(
	_In_ DWORD dwCtrl
);

void WINAPI ServiceMain(
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





