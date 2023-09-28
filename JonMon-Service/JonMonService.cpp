#include <Windows.h>
#include <iostream>
#include <setupapi.h>
#include "service.h"
#include "etwMain.h"
#pragma comment(lib, "setupapi.lib")

int wmain(int argc, wchar_t* argv[])
{
	std::wstring VariantString(argv[1]);
	if (VariantString == L"-etw") {
		//Copying resource file to C:\Windows and installing manifest
		BOOL FileCopy = CopyFileW(L"JonMon.dll", L"C:\\Windows\\JonMon.dll", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon.dll did not copy to C:\\Windows\\JonMon.dll\n");
		}
		else {
			printf("[*] JonMon.dll copied\n");
		}
		DWORD status = InstallManifest();
		TraceEvent();
	}
	if (VariantString == L"-i") {
		//Copying resource file to C:\Windows and installing manifest
		printf("[*] Starting JonMon Installation Process....\n");

		BOOL FileCopy = CopyFileW(L"JonMon.dll", L"C:\\Windows\\JonMon.dll", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon.dll did not copy to C:\\Windows\\JonMon.dll\n");
		}
		else {
			printf("[*] JonMon.dll copied\n");
		}
		DWORD status = InstallManifest();

		LPWSTR CurrentDirectory = new WCHAR[MAX_PATH];

		//Installing JonMonDrv Service: 
		FileCopy = CopyFileW(L"JonMon.sys", L"C:\\Windows\\JonMon.sys", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon.sys did not copy to C:\\Windows\\JonMon.sys\n");
		}
		else {
			printf("[*] JonMon.sys copied\n");
		}

		FileCopy = CopyFileW(L"JonMon.inf", L"C:\\Windows\\JonMon.inf", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon.inf did not copy to C:\\Windows\\JonMon.inf\n");
		}
		else {
			printf("[*] JonMon.inf copied\n");
		}
		FileCopy = CopyFileW(L".\\Extensions\\JonMon-Ext1.dll", L"C:\\Windows\\JonMon-Ext1.dll", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon-Ext1.dlll did not copy to C:\\Windows\\JonMon-Ext1.dlll\n");
		}
		else {
			printf("[*] JonMon-Ext1.dll copied\n");
		}

		printf("[*] Installing JonMonDrv Service....\n");
		InstallHinfSectionW(NULL, NULL, TEXT("DefaultInstall 132 C:\\Windows\\JonMon.inf"), 0);
		printf("[*] JonMonDrv Service Installed\n");


		FileCopy = CopyFileW(L"JonMon-Service.exe", L"C:\\Windows\\JonMon-Service.exe", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon-Service.exe did not copy to C:\\Windows\\JonMon-Service.exe\n");
		}
		else {
			printf("[*] JonMon-Service.exe copied\n");
		}
		status = CreateCustomService(L"JonMon", L"C:\\Windows\\JonMon-Service.exe -s", SERVICE_WIN32_OWN_PROCESS); //Need to change this to the actual path of the service
		if (status != 0) {
			printf("[-] InstallService Failed\n");
		}
		status = StartCustomService(L"JonMon");
		if (status != 0) {
			printf("[-] Failed to start JonMon\n");
		}

	}
	if (VariantString == L"-s") {
		DWORD status = StartCustomService(L"JonMonDrv");
		if (status != 0) {
			printf("[-] Failed to start JonMonDrv\n");
		}
		//Starting service for JonMon-Service.exe
		SERVICE_TABLE_ENTRYW serviceTable[] =
		{
			{ const_cast <LPWSTR>(L""), (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
			{ NULL, NULL }
		};
		if (!StartServiceCtrlDispatcherW(serviceTable))
		{
			// Failed to start service control dispatcher
			return GetLastError();
		}
	}
	if (VariantString == L"-u") {
		printf("[*] Starting JonMon Uninstallation Process....\n");
		DWORD status = StopCustomService(L"JonMonDrv");
		if (status != 0) {
			printf("[-] Failed to stop JonMonDrv\n");
		}
		status = DeleteCustomService(L"JonMonDrv");
		if (status != 0) {
			printf("[-] Failed to delete JonMonDrv\n");
		}
		status = StopCustomService(L"JonMon");
		if (status != 0) {
			printf("[-] Failed to stop JonMon\n");
		}
		status = DeleteCustomService(L"JonMon");
		if (status != 0) {
			printf("[-] Failed to delete JonMon\n");
		}

		status = StopETWTrace();

		printf("[*] Removing Files....\n");
		DeleteFileW(L"C:\\Windows\\JonMon.sys");
		DeleteFileW(L"C:\\Windows\\JonMon-Service.exe");
		DeleteFileW(L"C:\\Windows\\JonMon-Ext1.dll");
		DeleteFileW(L"C:\\Windows\\JonMon.inf");
		DeleteFileW(L"C:\\Windows\\System32\\drivers\\JonMon.sys");

		printf("[*] JonMon Uninstallation Complete\n");

	}
	if (VariantString == L"-h") {
		printf("Usage: 'JonMon-Service.exe -etw' will start an ETW trace called JonMon to collect events from various providers\n");
		printf("Usage: 'JonMon-Service.exe -i' will install the JonMon Services and Driver\n");
		printf("Usage: 'JonMon-Service.exe -s' will start the JonMon Services and Driver\n");
		printf("Usage: 'JonMon-Service.exe -u' will stop/uninstall all the JonMon Services\n");
	}

	return 0;
}