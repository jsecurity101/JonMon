#include <Windows.h>
#include <thread>
#include "service.h"
#include "config.h"
#include "etwMain.h"


SERVICE_STATUS_HANDLE g_hServiceStatus = NULL;
SERVICE_STATUS g_ServiceStatus = { 0 };



//
// JonMon TraceLogging Provider Information
//
TRACELOGGING_DECLARE_PROVIDER(g_hJonMon);

TRACELOGGING_DEFINE_PROVIDER(g_hJonMon, "JonMon",
    (0xdd82bf6f, 0x5295, 0x4541, 0x96, 0x8d, 0x8c, 0xac, 0x58, 0xe5, 0x72, 0xe4));


VOID WINAPI ServiceCtrlHandler(
    _In_ DWORD dwCtrl
)
{
    switch (dwCtrl)
    {
    case SERVICE_CONTROL_STOP:
        // Update the service status
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 0;
        g_ServiceStatus.dwWaitHint = 0;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

        // Perform service-specific cleanup here

        // Update the service status
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 0;
        g_ServiceStatus.dwWaitHint = 0;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

        EventUnregisterJonMon();

        break;

    case SERVICE_CONTROL_PAUSE:
        // Update the service status
        g_ServiceStatus.dwCurrentState = SERVICE_PAUSE_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 0;
        g_ServiceStatus.dwWaitHint = 0;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

        // Perform service-specific pause here

        // Update the service status
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        g_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 0;
        g_ServiceStatus.dwWaitHint = 0;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

        break;

    case SERVICE_CONTROL_CONTINUE:
        // Update the service status
        g_ServiceStatus.dwCurrentState = SERVICE_CONTINUE_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 0;
        g_ServiceStatus.dwWaitHint = 0;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

        // Perform service-specific continue here

        // Update the service status
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 0;
        g_ServiceStatus.dwWaitHint = 0;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

        break;

    case SERVICE_CONTROL_SHUTDOWN:
        // Perform service-specific shutdown here
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 0;
        g_ServiceStatus.dwWaitHint = 0;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

        break;

    default:
        // Update the service status
        g_ServiceStatus.dwWin32ExitCode = ERROR_CALL_NOT_IMPLEMENTED;
        g_ServiceStatus.dwCheckPoint = 0;
        g_ServiceStatus.dwWaitHint = 0;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

        break;
    }

}

VOID WINAPI ServiceMain(
    _In_ DWORD argc, 
    _In_ LPTSTR* argv
) {

    DWORD protectionLevel = 0;

    g_hServiceStatus = RegisterServiceCtrlHandlerExA("JonMon", (LPHANDLER_FUNCTION_EX)ServiceCtrlHandler, NULL);
    if (g_hServiceStatus == NULL) {
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;

    if (!SetServiceStatus(g_hServiceStatus, &g_ServiceStatus)) {
        return;
    }

    //
    // Register JonMon Providers
    //
    EventRegisterJonMon();
    TraceLoggingRegister(g_hJonMon);

    EventSchema_Full eventSchema = { 0 };
    int result = ConfigFile(argv[1], &eventSchema);
    if (result != 0) {
        printf("Failed to read configuration file\n");
        return;
    }

    if (eventSchema.TokenImpersonation_Events)
    {
        LoadExtensions();
    }

    protectionLevel = ProtectionCheck();
    if (protectionLevel != 31) {
		ChangePPL();
	}
   
    std::thread protectionCheck(ProtectionCheck);
    protectionCheck.detach();


    

    TraceEvent(L"JonMon", JonMonGuid, &eventSchema);
   
    

}

DWORD ProtectionCheck()
{
    Sleep(5000);
    DWORD protectionLevel = 0;
    do {
        PROCESS_PROTECTION_LEVEL_INFORMATION protectionInfo = { 0 };
        if (GetProcessInformation(GetCurrentProcess(), ProcessProtectionLevelInfo, &protectionInfo, sizeof(protectionInfo))) {
            if (protectionInfo.ProtectionLevel != 5) {
                protectionLevel = 1;
                TraceLoggingWrite(
                    g_hJonMon,
                    "102",
                    TraceLoggingInt32(102, "EventID"),
                    TraceLoggingBool(TRUE, "JonMon Protection Level Changed")
                );
            }
        }
        else {
            printf("Failed to retrieve PPL. Error code: %lu\n", GetLastError());
            TraceLoggingWrite(
                g_hJonMon,
                "102",
                TraceLoggingInt32(102, "EventID"),
                TraceLoggingBool(FALSE, "JonMon Protection Level Changed")
            );
            return 1;
        }
    } while (protectionLevel == 0);
    return 0;
}

VOID ChangePPL() {

    HANDLE hDevice = CreateFile(L"\\\\.\\JonMon", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Error %u\n", GetLastError());
        return;
    }
    DWORD bytes;
    HANDLE hProcess;
    if (DeviceIoControl(hDevice, IOCTL_CHANGE_PROTECTION_LEVEL_PROCESS, NULL, NULL, NULL, NULL, NULL, NULL)) {
        OutputDebugStringW(L"Protection Level Changed\n");
    }
    else {
        printf("Error: %u\n", GetLastError());
    }

    CloseHandle(hDevice);
}

VOID LoadExtensions()
{
    
    //
    // Loading JonMon-Ext1.dll to capture token impersonation events
    //
    typedef VOID(__stdcall* TokenImpersonationCheck)();

    HMODULE hModule = LoadLibrary(L"JonMon-Ext1.dll");
    if (hModule == NULL) {
        OutputDebugString(L"Failed to load JonMon-Ext1.dll");
        return;
    }

    //
    // Execute the TokenImpersonationCheck function 
    //
    TokenImpersonationCheck TokenImpersonationCheckFunc = (TokenImpersonationCheck)GetProcAddress(hModule, "TokenImpersonationCheck");
    if (TokenImpersonationCheckFunc == NULL)
    {
        OutputDebugString(L"Failed to get TokenImpersonationCheck function address");
        return;
    }

    //
    // Call the TokenImpersonationCheck function and give it a thread
    //
    std::thread tokenImpersonationCheckThread(TokenImpersonationCheckFunc);
    tokenImpersonationCheckThread.detach();
}

DWORD CreateCustomService(
    _In_ LPCWSTR ServiceName, 
    _In_ LPCWSTR ImagePath, 
    _In_ DWORD dwServiceType
) {

    SC_HANDLE hSCManager = nullptr;
    SC_HANDLE hService = nullptr;
    DWORD dwError = 0;

    printf("[*] Creating Service %ws....\n", ServiceName);

    hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == nullptr) {
        printf("[-] Service creation failed on OpenSCManager\n");
        dwError = GetLastError();
        goto Exit;
    }
    hService = CreateService(hSCManager, ServiceName, ServiceName, SC_MANAGER_CREATE_SERVICE, dwServiceType, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, ImagePath, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (hService == nullptr) {
        printf("[-] Service creation failed on CreateService\n");
        dwError = GetLastError();
        goto Exit;
    }
    printf("[*] Service %ws created successfully\n", ServiceName);
Exit:
    if(hSCManager != nullptr)
    {
        CloseServiceHandle(hSCManager);
    }
    if(hService != nullptr)
    {
        CloseServiceHandle(hService);
    }
    return 0;
}

DWORD StartCustomService(
    _In_ LPCWSTR ServiceName
) {
    SC_HANDLE hSCManager = nullptr;
    SC_HANDLE hService = nullptr;
    DWORD dwError = 0;

    printf("[*] Starting Service %ws....\n", ServiceName);
    hSCManager = OpenSCManager(nullptr, nullptr, SERVICE_START);
    if (hSCManager == nullptr) {
        printf("[-] Start service failed on OpenSCManager\n");
        dwError = GetLastError();
        goto Exit;
    }
    hService = OpenService(hSCManager, ServiceName, SERVICE_START);
    if (hService == nullptr) {
        printf("[-] Start service failed on OpenService\n");
        dwError = GetLastError();
        goto Exit;
    }

    if (ServiceName == L"JonMon")
    {
        LPCWSTR serviceArgs[] = { L"C:\\Windows\\JonMonConfig.json"};
       
        if (!StartService(hService, 1, serviceArgs)) {
            printf("[-] Start service failed on %ws\n", ServiceName);
            dwError = GetLastError();
            goto Exit;
        }
        printf("[*] Service %ws started successfully\n", ServiceName);
    }
    else if (ServiceName == L"JonMonDrv")
    {
        if (!StartService(hService, 0, nullptr)) {
            printf("[-] Start service failed on %ws\n", ServiceName);
            dwError = GetLastError();
            goto Exit;
        }
        printf("[*] Service %ws started successfully\n", ServiceName);
    }
    

Exit:
    if (hSCManager != nullptr)
    {
		CloseServiceHandle(hSCManager);
	}
    if (hService != nullptr)
    {
		CloseServiceHandle(hService);
	}
    return 0;
}

DWORD StopCustomService(
    _In_ LPCWSTR ServiceName
) {
    printf("[*] Stopping Service %ws....\n", ServiceName);
    SC_HANDLE hSCManager = nullptr;
    hSCManager = OpenSCManager(nullptr, nullptr, SERVICE_STOP);
    if (hSCManager == nullptr) {
        printf("[-] OpenSCManager Failed");
        return GetLastError();
    }
    SC_HANDLE hService = OpenService(hSCManager, ServiceName, SERVICE_STOP);
    if (hService == nullptr) {
        printf("[-] OpenService Failed\n");
        CloseServiceHandle(hSCManager);
        return GetLastError();
    }
    SERVICE_STATUS status;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        printf("[-] ControlService Failed\n");
        CloseServiceHandle(hSCManager);
        CloseServiceHandle(hService);
        return GetLastError();
    }
    CloseServiceHandle(hSCManager);
    CloseServiceHandle(hService);

    if (g_hJonMon != NULL)
    {
        TraceLoggingUnregister(g_hJonMon);
    }
    

    printf("[*] Service %ws stopped successfully\n", ServiceName);

    return 0;
}

DWORD DeleteCustomService(
    _In_ LPCWSTR ServiceName
) {
    printf("[*] Deleting Service %ws....\n", ServiceName);
    SC_HANDLE hSCManager = nullptr;
    hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == nullptr) {
        printf("[-] OpenSCManager Failed\n");
        return GetLastError();
    }
    SC_HANDLE hService = OpenService(hSCManager, ServiceName, DELETE);
    if (hService == nullptr) {
        printf("[-] OpenService Failed\n");
        CloseServiceHandle(hSCManager);
        return GetLastError();
    }
    if (!DeleteService(hService)) {
        printf("[-] DeleteService Failed\n");
        CloseServiceHandle(hSCManager);
        CloseServiceHandle(hService);
        return GetLastError();
    }
    CloseServiceHandle(hSCManager);
    CloseServiceHandle(hService);
    printf("[*] Service %ws deleted successfully\n", ServiceName);
    return 0;
}

DWORD UninstallManifest() {

    printf("[*] Uninstalling Manifest....\n");
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    wchar_t cmdLine[] = L"C:\\Windows\\System32\\wevtutil.exe um JonMon.man";
    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess Failed");
        return GetLastError();
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[*] Manifest Uninstalled....\n");

    return 0;
}

DWORD InstallManifest() {
    printf("[*] Installing Manifest....\n");
    DWORD dwRet = UninstallManifest();
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    wchar_t cmdLine[] = L"C:\\Windows\\System32\\wevtutil.exe im JonMon.man";
    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess Failed");
        return GetLastError();
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("[*] Manifest Installed....\n");

    return 0;
}