#include <Windows.h>
#include <psapi.h>
#include "context.h"
#include <sstream>
#include <vector>
#include <mutex>
#include <psapi.h>

std::vector<ProcessInformation> processList;

std::vector<ProcessInformation> initialProcessList;

//
// Mutexes to protect access to the process lists
//
std::mutex processListMutex;  // Mutex to protect access to processList

std::mutex initialProcessListMutex;  // Mutex to protect access to initialProcessList

//
// Function to enumerate initial processes running on the system and store them in the initialProcessList
//
void InitialProcesses()
{
    PTokenInformation tokenInformation = NULL;
    PProcessInformation processInformation = NULL;
    HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process
    if (!Process32First(hProcessSnapshot, &pe32)) {
        goto Exit;
    }

    // Loop through the processes in the snapshot
    do {
        // Get the process ID
        DWORD processID = pe32.th32ProcessID;
        //
        // if PID 4 is found, skip it
        //
        if (processID == 4)
        {
            continue;
        }
        WCHAR processName[MAX_PATH] = L"<unknown>";

        // Open the process to get its full path
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
        if (hProcess != NULL) {
            //
            // Get token information
            // 
            PTokenInformation tokenInformation = new TokenInformation();
            if (tokenInformation == NULL) {
                std::wcout << L"Error allocating memory for token information\n";
                continue;
            }

            DWORD status = GetUserInformation(processID, tokenInformation);
            if (status != 0) {
                std::wcout << L"GetUserInformation failed: " << status << std::endl;
                continue;
            }

            PProcessInformation processInformation = new ProcessInformation();
            if (processInformation == NULL) {
                std::wcout << L"Error allocating memory for process information\n";
                continue;
            }
            
            processInformation->processId = processID;
            processInformation->authenticationId = tokenInformation->authenticationId;
            processInformation->integrityLevel = tokenInformation->integrityLevel;
            processInformation->sessionId = tokenInformation->sessionId;
            processInformation->tokenType = tokenInformation->tokenType;
            processInformation->userName = tokenInformation->userName;
            processInformation->linkedAuthenticationId = tokenInformation->linkedAuthenticationId;

            // Get the full process image file name
            DWORD size = MAX_PATH;  // This should be set to the size of the buffer
            // Get the full process image file name
            if (QueryFullProcessImageName(hProcess, PROCESS_NAME_NATIVE, processName, &size)) {
                processInformation->processName = processName;
                std::lock_guard<std::mutex> lock(initialProcessListMutex);
                initialProcessList.push_back(*processInformation);
            }
            CloseHandle(hProcess);  // Close handle to process
        }

    } while (Process32Next(hProcessSnapshot, &pe32));  // Continue with the next process
    // Clean up the snapshot object
Exit:
    if (hProcessSnapshot != NULL)
    {
        CloseHandle(hProcessSnapshot);
    }
    if (tokenInformation != NULL)
    {
        delete(tokenInformation);
    }
    if (processInformation != NULL)
    {
        delete(processInformation);
    }

    return;

}

DWORD GetUserInformation(
    _In_ DWORD processId, 
    _In_ PTokenInformation tokenInformation
)
{
    DWORD status = 0;
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;
    DWORD dwLengthNeeded;
    PTOKEN_LINKED_TOKEN pTokenLinkedToken = NULL;

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess == NULL)
    {
        std::wcout << L"OpenProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        std::wcout << L"OpenProcessToken failed: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    status = GetTokenUserInfo(hToken, tokenInformation->userName);
    if (status != 0)
    {
        std::wcout << L"GetTokenUserInfo failed: " << status << std::endl;
        goto Exit;
    }

    // Get Token Type
    dwLengthNeeded = 0;
    if (!GetTokenInformation(hToken, TokenType, &tokenInformation->tokenType, sizeof(DWORD), &dwLengthNeeded))
    {
        status = GetLastError();
        std::wcout << L"GetTokenInformation (TokenType) failed: " << status << std::endl;
        goto Exit;
    }

    // Get Authentication ID
    status = GetAuthenticationId(hToken, &tokenInformation->authenticationId);
    if (status != 0)
    {
        std::wcout << L"GetAuthenticationId failed: " << status << std::endl;
        goto Exit;
    }

    // Get Session ID
    dwLengthNeeded = 0;
    if (!GetTokenInformation(hToken, TokenSessionId, &tokenInformation->sessionId, sizeof(DWORD), &dwLengthNeeded))
    {
        status = GetLastError();
        std::wcout << L"GetTokenInformation (SessionId) failed: " << status << std::endl;
        goto Exit;
    }

    // Get Linked Authentication ID
    pTokenLinkedToken = (PTOKEN_LINKED_TOKEN)LocalAlloc(LPTR, sizeof(TOKEN_LINKED_TOKEN));
    if (pTokenLinkedToken == NULL)
    {
        status = GetLastError();
        std::wcout << L"LocalAlloc for pTokenLinkedToken failed: " << status << std::endl;
        goto Exit;
    }

    if (!GetTokenInformation(hToken, TokenLinkedToken, pTokenLinkedToken, sizeof(TOKEN_LINKED_TOKEN), &dwLengthNeeded))
    {
        status = GetLastError();
        if (status == ERROR_NO_SUCH_LOGON_SESSION)
        {
            tokenInformation->linkedAuthenticationId.LowPart = 0;
            tokenInformation->linkedAuthenticationId.HighPart = 0;
        }
        else
        {
            std::wcout << L"GetTokenInformation (LinkedToken) failed: " << status << std::endl;
            goto Exit;
        }
    }
    else if (pTokenLinkedToken->LinkedToken != NULL)
    {
        status = GetAuthenticationId(pTokenLinkedToken->LinkedToken, &tokenInformation->linkedAuthenticationId);
        if (status != 0)
        {
            std::wcout << L"GetAuthenticationId (LinkedToken) failed: " << status << std::endl;
            goto Exit;
        }
    }
    else
    {
        tokenInformation->linkedAuthenticationId.LowPart = 0;
        tokenInformation->linkedAuthenticationId.HighPart = 0;
    }

    // Get Integrity Level
    status = GetMandatoryLabel(hToken, tokenInformation->integrityLevel);
    if (status != 0)
    {
        std::wcout << L"GetMandatoryLabel failed: " << status << std::endl;
        goto Exit;
    }

Exit:
    if (pTokenLinkedToken != NULL)
    {
        if (pTokenLinkedToken->LinkedToken != NULL)
        {
            CloseHandle(pTokenLinkedToken->LinkedToken);
        }
        LocalFree(pTokenLinkedToken);
    }
    if (hToken != NULL)
    {
        CloseHandle(hToken);
    }
    if (hProcess != NULL)
    {
        CloseHandle(hProcess);
    }

    return status;
}


//
// Query the process list to get the process name of a given process id
//
PProcessInformation GetProcessName(
    _In_ DWORD processId) {
    {
        std::lock_guard<std::mutex> lock(initialProcessListMutex);
        for (auto& process : initialProcessList) {
            if (process.processId == processId) {
                return &process;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(processListMutex);
        for (auto& process : processList) {
            if (process.processId == processId) {
                return &process;
            }
        }
    }

    return nullptr;
}


void ClearProcessList() {
    //
    // lock the process list using a mutex
    //
    std::lock_guard<std::mutex> lock(processListMutex);  // Locks the mutex

    //
    // Clear the existing processList3 to avoid duplication
    //
    processList.clear();

}

void GetProcessList() {
    // Take a snapshot of all processes in the system
    PTokenInformation tokenInformation = NULL;
    PProcessInformation processInformation = NULL;
    HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process
    if (!Process32First(hProcessSnapshot, &pe32)) {
        goto Exit;
    }

    // Loop through the processes in the snapshot
    do {
        DWORD processID = pe32.th32ProcessID;

        if (processID == 4)  // Skip PID 4
            continue;

        // Check if process already exists in initialProcessList or processList
        bool exists = false;
        for (const auto& process : initialProcessList) {
            if (process.processId == processID) {
                exists = true;
                break;
            }
        }
        if (exists)
        {
            continue;
        }

        for (const auto& process : processList) {
            if (process.processId == processID) {
                exists = true;
                break;
            }
        }
        if (exists)
        {
            continue;
        }

        WCHAR processName[MAX_PATH] = L"<unknown>";
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
        if (hProcess != NULL) {
            // Allocate token information
            tokenInformation = new TokenInformation();
            if (tokenInformation == NULL) {
                std::wcout << L"Error allocating memory for token information\n";
                CloseHandle(hProcess);
                continue;
            }

            DWORD status = GetUserInformation(processID, tokenInformation);
            if (status != 0) {
                std::wcout << L"GetUserInformation failed: " << status << std::endl;
                delete tokenInformation;
                tokenInformation = nullptr;
                CloseHandle(hProcess);
                continue;
            }

            // Allocate process information
            processInformation = new ProcessInformation();
            if (processInformation == NULL) {
                std::wcout << L"Error allocating memory for process information\n";
                delete tokenInformation;
                tokenInformation = nullptr;
                CloseHandle(hProcess);
                continue;
            }

            // Populate processInformation
            processInformation->processId = processID;
            processInformation->authenticationId = tokenInformation->authenticationId;
            processInformation->integrityLevel = tokenInformation->integrityLevel;
            processInformation->sessionId = tokenInformation->sessionId;
            processInformation->tokenType = tokenInformation->tokenType;
            processInformation->userName = tokenInformation->userName;
            processInformation->linkedAuthenticationId = tokenInformation->linkedAuthenticationId;

            // Get the process name
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageName(hProcess, PROCESS_NAME_NATIVE, processName, &size)) {
                processInformation->processName = processName;
                std::lock_guard<std::mutex> lock(processListMutex);
                processList.push_back(*processInformation);
            }

            // Free allocated memory for this iteration
            delete tokenInformation;
            delete processInformation;
            tokenInformation = nullptr;
            processInformation = nullptr;

            CloseHandle(hProcess);  // Close handle to process
        }

    } while (Process32Next(hProcessSnapshot, &pe32));  // Continue with the next process

    // Clean up and exit
Exit:
    if (hProcessSnapshot != NULL) {
        CloseHandle(hProcessSnapshot);
    }
}

//
// Function to periodically update the process list every second
//
void UpdateProcessListPeriodically() {
    while (true) {
        GetProcessList();
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // trying to be fast because of sacraficial processes
    }
}

void ClearListPeriodically() {
    while (true) {
        ClearProcessList();
        //
        // Pause for 5 seconds to allow the process list to be updated
        //
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

DWORD GetTokenUserInfo(
    _In_ HANDLE hToken, 
    _In_ std::wstring& fullUserName
)
{
    PTOKEN_USER pTokenUser = NULL;
    DWORD status = 0;
    DWORD dwLengthNeeded = 0;
    DWORD dwSizeName;
    DWORD dwSizeDomain;
    WCHAR szName[256];
    WCHAR szDomain[256];
    WCHAR userName[514];
    SID_NAME_USE eUse;

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLengthNeeded))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            std::wcout << L"GetTokenInformation failed: " << GetLastError() << std::endl;
            status = GetLastError();
            goto Exit;
        }
    }
    pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwLengthNeeded);
    if (pTokenUser == NULL)
    {
        std::wcout << L"LocalAlloc failed: " << GetLastError() << std::endl;
        status = GetLastError();
        goto Exit;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLengthNeeded, &dwLengthNeeded))
    {
        std::wcout << L"GetTokenInformation failed: " << GetLastError() << std::endl;
        status = GetLastError();
        goto Exit;
    }

    dwSizeName = 256;
    dwSizeDomain = 256; 

    if (!LookupAccountSid(NULL, pTokenUser->User.Sid, szName, &dwSizeName, szDomain, &dwSizeDomain, &eUse))
    {
        std::wcout << L"LookupAccountSid failed: " << GetLastError() << std::endl;
        status = GetLastError();
        goto Exit;
    }
    //
    // Combine the domain and user name
    //
    wcscpy_s(userName, szDomain);
    wcscat_s(userName, L"\\");
    wcscat_s(userName, szName);

    userName[513] = L'\0';

    fullUserName.assign(userName);


Exit:
    if (pTokenUser != NULL)
    {

        LocalFree(pTokenUser);
    }
    return status;
}

DWORD GetAuthenticationId(
    _In_ HANDLE hToken, 
    _In_ PLUID authId
)
{
    DWORD status = 0;
    DWORD dwLengthNeeded = 0;
    PTOKEN_STATISTICS pTokenStatistics = NULL;

    *authId = { 0 };

    if (!GetTokenInformation(hToken, TokenStatistics, NULL, 0, &dwLengthNeeded))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            std::wcout << L"GetTokenInformation failed: " << GetLastError() << std::endl;
            status = GetLastError();
            goto Exit;
        }
    }

    pTokenStatistics = (PTOKEN_STATISTICS)LocalAlloc(LPTR, dwLengthNeeded);
    if (pTokenStatistics == NULL)
    {
        std::wcout << L"LocalAlloc failed: " << GetLastError() << std::endl;
        status = GetLastError();
        goto Exit;
    }

    if (!GetTokenInformation(hToken, TokenStatistics, pTokenStatistics, dwLengthNeeded, &dwLengthNeeded))
    {
        status = GetLastError();
        if (status != ERROR_NO_SUCH_LOGON_SESSION)
        {
            std::wcout << L"GetTokenInformation failed: " << status << std::endl;
        }
        goto Exit;
    }

    // Successfully retrieved token statistics; assign AuthenticationId
    *authId = pTokenStatistics->AuthenticationId;

Exit:
    if (pTokenStatistics != NULL)
    {
        LocalFree(pTokenStatistics);
    }
    return status;
}


DWORD GetMandatoryLabel(
    _In_ HANDLE hToken, 
    _In_ std::wstring& integrityLevel
)
{
    DWORD status = 0;
    DWORD dwLengthNeeded = 0;
    PTOKEN_MANDATORY_LABEL pTokenMandatoryLabel = NULL;
    DWORD dwIntegrityLevel = 0;
    WCHAR szIntegrityLevel[1024] = L"Unknown";  // Default value for unknown levels

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            std::wcout << L"GetTokenInformation failed: " << GetLastError() << std::endl;
            status = GetLastError();
            goto Exit;
        }
    }

    pTokenMandatoryLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLengthNeeded);
    if (pTokenMandatoryLabel == NULL)
    {
        std::wcout << L"LocalAlloc failed: " << GetLastError() << std::endl;
        status = GetLastError();
        goto Exit;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenMandatoryLabel, dwLengthNeeded, &dwLengthNeeded))
    {
        std::wcout << L"GetTokenInformation failed: " << GetLastError() << std::endl;
        status = GetLastError();
        goto Exit;
    }

    // Get integrity level RID from SID
    dwIntegrityLevel = *GetSidSubAuthority(pTokenMandatoryLabel->Label.Sid, 0);

    // Determine integrity level description
    if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
    {
        wcscpy_s(szIntegrityLevel, L"Low");
    }
    else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID)
    {
        wcscpy_s(szIntegrityLevel, L"Medium");
    }
    else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID)
    {
        wcscpy_s(szIntegrityLevel, L"High");
    }
    else if (dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID)
    {
        wcscpy_s(szIntegrityLevel, L"System");
    }

    // Assign the integrity level to the output parameter
    integrityLevel.assign(szIntegrityLevel);

Exit:
    if (pTokenMandatoryLabel != NULL)
    {
        LocalFree(pTokenMandatoryLabel);
    }

    return status;
}
