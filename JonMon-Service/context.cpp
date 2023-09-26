#include <Windows.h>
#include <psapi.h>
#include "context.h"
#include <sstream>
#include <iostream>

int GetTokenUser(
    _In_ DWORD ProcessId, 
    _Out_ wchar_t** Username
) {
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;
    PTOKEN_USER pTokenUser = NULL;
    int dwErrorCode = ERROR_SUCCESS;
    SID_NAME_USE SidType;
    wchar_t Name[128];
    wchar_t Domain[128];
    DWORD cchName = 128;
    DWORD cchDomain = 128;
    DWORD dwSize = 0;

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        std::cout << "OpenProcess Failed" << std::endl;
        dwErrorCode = GetLastError();
        goto Exit;
    }
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        OutputDebugStringW(L"OpenProcessTokenFailed\n");
        dwErrorCode = GetLastError();
        goto Exit;
    }

    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (dwSize == 0) {
        OutputDebugStringW(L"GetTokenInformation Failed\n");
        dwErrorCode = GetLastError();
        goto Exit;
    }
    pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
    if (pTokenUser == NULL) {
        OutputDebugStringW(L"LocalAlloc Failed\n");
        dwErrorCode = GetLastError();
        goto Exit;
    }
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        OutputDebugStringW(L"GetTokenInformation Failed\n");
        dwErrorCode = GetLastError();
        goto Exit;
    }

    if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, Name, &cchName, Domain, &cchDomain, &SidType)) {
        OutputDebugStringW(L"LookupAccountSidW Failed\n");
        dwErrorCode = GetLastError();
        goto Exit;

    }
    *Username = new wchar_t[256]; // Adjust the size as needed (512 in this case)
    wsprintfW(*Username, L"%s\\%s", Domain, Name);
    if (sizeof(*Username) > 256) {
        OutputDebugStringW(L"Username is too long\n");
        goto Exit;
    }

Exit:
    if (hToken != NULL) {
        CloseHandle(hToken);
    }
    if (pTokenUser != NULL)
    {
        LocalFree(pTokenUser);
    }
    if (hProcess != NULL)
    {
        CloseHandle(hProcess);
    }
    return dwErrorCode;
}

int GetImagePath(
    _In_ DWORD ProcessId,
    _Out_ wchar_t** ImagePath
) {
    int dwErrorCode = ERROR_SUCCESS;
    wchar_t* pImagePath = new wchar_t[MAX_PATH];
    DWORD dwSize = MAX_PATH;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (hProcess == NULL) {
        std::wcout << L"OpenProcess Failed\n";
        std::wcout << L"ProcessID " << ProcessId << std::endl;
        return ERROR_INVALID_HANDLE;
    }

    // getting image path via GetModuleFileNameEx
    while (true) {
        if (GetModuleFileNameEx(hProcess, NULL, pImagePath, MAX_PATH) == 0) {
            dwErrorCode = GetLastError();
            if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER) {
                // The buffer was too small, double the size and try again
                delete[] pImagePath;
                dwSize *= 2;
                pImagePath = new wchar_t[dwSize];
                if (pImagePath == nullptr) {
                    dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
                    break;
                }
            }
            else {
                dwErrorCode = GetLastError();
                break;
            }
        }
        else {
            break;
        }
    }

    if (dwErrorCode == ERROR_SUCCESS) {
        // Allocate memory for the image path and copy the value to the output parameter
        size_t nLength = wcslen(pImagePath) + 1;
        *ImagePath = new wchar_t[nLength];
        if (*ImagePath == nullptr) {
            dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        }
        else {
            wcscpy_s(*ImagePath, nLength, pImagePath);
        }
    }

    // Clean up resources
    if (hProcess != NULL) {
        CloseHandle(hProcess);
    }
    if (pImagePath != NULL) {
        delete[] pImagePath;
    }
    return dwErrorCode;
}
