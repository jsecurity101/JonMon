#include <Windows.h>
#include <iostream>
#include <setupapi.h>
#include "etwMain.h"
#include "service.h"
#include "config.h"


#pragma comment(lib, "setupapi.lib")

int wmain(int argc, wchar_t* argv[])
{
	std::wstring VariantString(argv[1]);
	std::wstring ConfigPath = L"JonMonConfig.json";

	EventSchema_Full eventSchema = { 0 };

	if (argc == 3) {
		ConfigPath = argv[2];
	}

	BOOL FileCopy = CopyFileW(ConfigPath.c_str(), L"C:\\Windows\\JonMonConfig.json", FALSE);
	if (FileCopy != TRUE) {
		printf("[-] JonMonConfig.json did not copy to C:\\Windows\\JonMonConfig.json\n");
	}

	int result = ConfigFile(L"C:\\Windows\\JonMonConfig.json", &eventSchema);


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

		TraceEvent(L"JonMonDebug", JonMonDebugGuid, &eventSchema);
	}
	if (VariantString == L"-c")
	{ 
		std::wcout << L"JonMon EventSchema: " << std::endl;
		std::wcout << L"ProcessCreationEvents: " << (eventSchema.ProcessCreation_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"FileEvents: " << (eventSchema.File_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"ProcessTerminationEvents: " << (eventSchema.ProcessTermination_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"RegistryEvents: " << (eventSchema.Registry_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"ProcessHandleCreationEvents: " << (eventSchema.ProcessHandleCreation_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"ProcessHandleDuplicationEvents: " << (eventSchema.ProcessHandleDuplication_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"RemoteThreadCreationEvents: " << (eventSchema.RemoteThreadCreation_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"ImageLoadEvents: " << (eventSchema.ImageLoad_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"RPCEvents: " << (eventSchema.RPC_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"NetworkEvents: " << (eventSchema.Network_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"DotNetLoadEvents: " << (eventSchema.DotNetLoad_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"AMSIEvents: " << (eventSchema.AMSI_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"SchedTaskEvents: " << (eventSchema.SchedTask_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"WMIEventSubscriptionEvents: " << (eventSchema.WMIEventSubscription_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"CryptUnprotectEvents: " << (eventSchema.CryptUnprotect_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"ThreatIntelligenceEvents: " << (eventSchema.ThreatIntelligence_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"ThreatIntelligenceEvents RemoteReadProcessMemory: " << (eventSchema.ThreatIntelligence_Events_RemoteReadProcessMemory ? L"True" : L"False") << std::endl;
		std::wcout << L"ThreatIntelligenceEvents RemoteWriteProcessMemory: " << (eventSchema.ThreatIntelligence_Events_RemoteWriteProcessMemory ? L"True" : L"False") << std::endl;
		std::wcout << L"ThreatIntelligenceEvents RemoteVirtualAllocation: " << (eventSchema.ThreatIntelligence_Events_RemoteVirtualAllocation ? L"True" : L"False") << std::endl;
		std::wcout << L"ThreatIntelligenceEvents RemoteQueueUserAPC: " << (eventSchema.ThreatIntelligence_Events_RemoteQueueUserAPC ? L"True" : L"False") << std::endl;
		std::wcout << L"TokenImpersonationEvents: " << (eventSchema.TokenImpersonation_Events ? L"True" : L"False") << std::endl;
		std::wcout << L"ConfigVersion: " << eventSchema.ConfigVersion << std::endl;
		std::wcout << L"JonMonVersion: " << eventSchema.JonMonVersion << std::endl;

		EventSchema_KM eventSchemaKM = { 0 };
		eventSchemaKM.ConfigSet = eventSchema.ConfigSet;
		eventSchemaKM.ProcessCreation = eventSchema.ProcessCreation_Events;
		eventSchemaKM.ProcessTermination = eventSchema.ProcessTermination_Events;
		eventSchemaKM.ProcessHandleCreation = eventSchema.ProcessHandleCreation_Events;
		eventSchemaKM.ProcessHandleDuplication = eventSchema.ProcessHandleDuplication_Events;
		eventSchemaKM.RemoteThreadCreation = eventSchema.RemoteThreadCreation_Events;
		eventSchemaKM.ImageLoad = eventSchema.ImageLoad_Events;
		eventSchemaKM.File = eventSchema.File_Events;
		eventSchemaKM.Registry = eventSchema.Registry_Events;
		eventSchemaKM.ConfigVersion = eventSchema.ConfigVersion;
		eventSchemaKM.JonMonVersion = eventSchema.JonMonVersion;

	}
	if (VariantString == L"-i") {
		//Copying resource file to C:\Windows and installing manifest
		printf("[*] Starting JonMon Installation Process....\n");

		FileCopy = CopyFileW(L"JonMon.dll", L"C:\\Windows\\JonMon.dll", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon.dll did not copy to C:\\Windows\\JonMon.dll\n");
		}

		DWORD status = InstallManifest();
		if (status != 0) {
			printf("[-] InstallManifest Failed\n");
		}

		LPWSTR CurrentDirectory = new WCHAR[MAX_PATH];

		FileCopy = CopyFileW(L"JonMon.sys", L"C:\\Windows\\JonMon.sys", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon.sys did not copy to C:\\Windows\\JonMon.sys\n");
		}

		FileCopy = CopyFileW(L"JonMon-Service.exe", L"C:\\Windows\\JonMon-Service.exe", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon-Service.exe did not copy to C:\\Windows\\JonMon-Service.exe\n");
		}

		FileCopy = CopyFileW(L".\\Extensions\\JonMon-Ext1.dll", L"C:\\Windows\\JonMon-Ext1.dll", FALSE);
		if (FileCopy != TRUE) {
			printf("[-] JonMon-Ext1.dlll did not copy to C:\\Windows\\JonMon-Ext1.dlll\n");
		}
		else {
			printf("[*] JonMon-Ext1.dll copied\n");
		}

		printf("[*] Installing JonMonDrv Service....\n");
		status = CreateCustomService(L"JonMonDrv", L"C:\\Windows\\JonMon.sys", SERVICE_KERNEL_DRIVER);
		printf("[*] JonMonDrv Service Installed\n");



		//
		// --- Start Minifilter Settings ---
		//
		printf("[*] Adding Minifilter registry values....\n");

		HKEY hKey;
		status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\JonMonDrv", 0, KEY_SET_VALUE, &hKey);
		if (hKey == NULL || status != 0) {
			printf("[-] Failed to open registry key to JonMonDrv\n");
		}

		DWORD value = 3;
		status = RegSetKeyValueW(hKey, NULL, L"SupportedFeatures", REG_DWORD, &value, sizeof(value));
		if (status != ERROR_SUCCESS) {
			printf("[-] Failed to set registry value for SupportedFeatures\n");
		}

		RegCloseKey(hKey);

		hKey = NULL;
		LONG lRes = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\JonMonDrv\\Instances", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
		if (lRes != ERROR_SUCCESS) {
			printf("[-] Failed to create registry key for Instances\n");
		}

		lRes = RegSetValueExW(hKey, L"DefaultInstance", 0, REG_SZ, (const BYTE*)L"JonMon Instance", sizeof(L"JonMon Instance"));
		if (lRes != ERROR_SUCCESS) {
			printf("[-] Failed to set registry value for DefaultInstance\n");
		}

		RegCloseKey(hKey);
		
		hKey = NULL;
		lRes = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\JonMonDrv\\Instances\\JonMon Instance", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
		if (lRes != ERROR_SUCCESS) {
			printf("[-] Failed to create registry key for JonMon Instance\n");
		}

		lRes = RegSetValueExW(hKey, L"Altitude", 0, REG_SZ, (const BYTE*)L"385202", sizeof(L"385202"));
		if (lRes != ERROR_SUCCESS) {
			printf("[-] Failed to set registry value for Altitude\n");
		}


		value = 0;
		status = RegSetKeyValueW(hKey,NULL,L"Flags",REG_DWORD,&value,sizeof(value));
		if (status != ERROR_SUCCESS) {
			printf("[-] Failed to set registry value for Flags\n");
		}
		RegCloseKey(hKey);

		printf("[*] Minifilter registry values added\n");

		//
		// --- Stop Minifilter Settings ---
		//

		status = CreateCustomService(L"JonMon", L"C:\\Windows\\JonMon-Service.exe -s", SERVICE_WIN32_OWN_PROCESS);
		if (status != 0) {
			printf("[-] InstallService Failed\n");
		}
		status = StartCustomService(L"JonMon");
		if (status != 0) {
			printf("[-] Failed to start JonMon\n");
		}

		EventSchema_KM eventSchemaKM = { 0 };
		eventSchemaKM.ConfigSet = eventSchema.ConfigSet;
		eventSchemaKM.ProcessCreation = eventSchema.ProcessCreation_Events;
		eventSchemaKM.ProcessTermination = eventSchema.ProcessTermination_Events;
		eventSchemaKM.ProcessHandleCreation = eventSchema.ProcessHandleCreation_Events;
		eventSchemaKM.ProcessHandleDuplication = eventSchema.ProcessHandleDuplication_Events;
		eventSchemaKM.RemoteThreadCreation = eventSchema.RemoteThreadCreation_Events;
		eventSchemaKM.ImageLoad = eventSchema.ImageLoad_Events;
		eventSchemaKM.File = eventSchema.File_Events;
		eventSchemaKM.Registry = eventSchema.Registry_Events;
		eventSchemaKM.ConfigVersion = eventSchema.ConfigVersion;
		eventSchemaKM.JonMonVersion = eventSchema.JonMonVersion;

		HANDLE hDevice = CreateFile(L"\\\\.\\JonMon", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hDevice == INVALID_HANDLE_VALUE) {
			printf("Error %u\n", GetLastError());
			goto Exit;
		}
		DeviceIoControl(hDevice, IOCTL_EVENT_CONFIGURATION, &eventSchemaKM, sizeof(eventSchemaKM), NULL, 0, NULL, NULL);
		CloseHandle(hDevice);
	}
	if (VariantString == L"-s") {
		DWORD status = StartCustomService(L"JonMonDrv");
		if (status != 0) {
			printf("[-] Failed to start JonMonDrv\n");
		}
		//Starting service for JonMon-Service.exe
		SERVICE_TABLE_ENTRYW serviceTable[] =
		{
			{ const_cast <LPWSTR>(L""), (LPSERVICE_MAIN_FUNCTIONW)ServiceMain }
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

		printf("[*] Deregestering JonMon Provider\n");

		status = StopETWTrace();

		printf("[*] Removing Files....\n");
		DeleteFileW(L"C:\\Windows\\JonMon.sys");
		DeleteFileW(L"C:\\Windows\\JonMon-Service.exe");
		DeleteFileW(L"C:\\Windows\\JonMon-Ext1.dll");
		DeleteFileW(L"C:\\Windows\\JonMon.dll");
		DeleteFileW(L"C:\\Windows\\JonMonConfig.json");

		printf("[*] JonMon Uninstallation Complete\n");

		

	}
	if (VariantString == L"-h") {
		printf("Usage: 'JonMon-Service.exe -etw' will start an ETW trace called JonMon to collect events from various providers\n");
		printf("Usage: 'JonMon-Service.exe -i' will install the JonMon Services and Driver\n");
		printf("Usage: 'JonMon-Service.exe -s' will start the JonMon Services and Driver\n");
		printf("Usage: 'JonMon-Service.exe -u' will stop/uninstall all the JonMon Services\n");
		printf("Usage: 'JonMon-Service.exe -c' will read the configuration file\n");
	}

Exit:

	return 0;
}