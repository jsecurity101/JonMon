//
// Author: Jonathan Johnson (@jsecurity101)
// JonMon-Ext1.dll. This is the DLL that will be loaded by JonMon-Service.dll and will query threads to see if they are impersonating a token.
//

#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <evntprov.h>
#include "tlhelp32.h"
#include "sddl.h"
#include "dllmain.h"
#include "../../../JonMonProvider/jonmon.h"

//
// JonMon TraceLogging Provider Information
//
TRACELOGGING_DECLARE_PROVIDER(g_hJonMon);

TRACELOGGING_DEFINE_PROVIDER(g_hJonMon, "JonMon",
    (0xdd82bf6f, 0x5295, 0x4541, 0x96, 0x8d, 0x8c, 0xac, 0x58, 0xe5, 0x72, 0xe4));

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DWORD IntegritySID(HANDLE hToken, PDWORD *IntegrityLevel) {

    PSID pIntegritySid = NULL;
    PTOKEN_MANDATORY_LABEL  pIntegrityLabel = NULL;
    DWORD retValue = 0;

    //
    // pull thread tokens integrity level
    //
    DWORD dwTokenInfoSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwTokenInfoSize);

    if (dwTokenInfoSize == 0)
    {
        printf("GetTokenInformation failed (%d)\n", GetLastError());
        retValue = 1;
        goto Exit;
    }

    //
    // Allocate memory for the TOKEN_MANDATORY_LABEL structure
    //
    pIntegrityLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwTokenInfoSize);

    if (!pIntegrityLabel)
    {
        printf("Memory allocation failed\n");
        retValue = 1;
        goto Exit;
    }

    //
    // Get the TOKEN_MANDATORY_LABEL structure
    //
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pIntegrityLabel, dwTokenInfoSize, &dwTokenInfoSize))
    {
        printf("GetTokenInformation failed (%d)\n", GetLastError());
        retValue = 1;
        goto Exit;
    }

    //
    // Extract the integrity level SID from the TOKEN_MANDATORY_LABEL structure
    //
    pIntegritySid = pIntegrityLabel->Label.Sid;

    // Convert the integrity level SID to a human-readable string


    *IntegrityLevel = GetSidSubAuthority(pIntegritySid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pIntegritySid) - 1));

Exit:
    //
    //  Free resources
    //
    if (pIntegrityLabel != nullptr)
    {
        LocalFree(pIntegrityLabel);
    }

    return retValue;
}

DWORD TokenUserName(HANDLE hToken, LPWSTR* pStringSid)
{
    DWORD retValue = 0;
    PTOKEN_USER processTokenUser = NULL;
    DWORD dwTokenInfoSize = 0;
    LPWSTR lpName = NULL;
    LPWSTR lpDomain = NULL;
    DWORD dwNameSize = 0;
    DWORD dwDomainSize = 0;
    SID_NAME_USE eSidType;
    PSID pUserSid = NULL;
    DWORD dwSize = 0;

    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenInfoSize);

    if (dwTokenInfoSize == 0)
    {
        printf("GetTokenInformation failed (%d)\n", GetLastError());
        retValue = 1;
        goto Exit;
    }

    // Allocate memory for the TOKEN_USER structure
    processTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwTokenInfoSize);
    if (processTokenUser == NULL)
    {
        printf("Memory allocation failed\n");
        retValue = 1;
        goto Exit;
    }

    // Get the TOKEN_USER structure
    if (!GetTokenInformation(hToken, TokenUser, processTokenUser, dwTokenInfoSize, &dwTokenInfoSize))
    {
        printf("GetTokenInformation failed (%d)\n", GetLastError());
        retValue = 1;
        goto Exit;
    }

    // Extract the user SID from the TOKEN_USER structure
    pUserSid = processTokenUser->User.Sid;

    // First call to LookupAccountSid to get the buffer sizes
    LookupAccountSidW(NULL, pUserSid, NULL, &dwNameSize, NULL, &dwDomainSize, &eSidType);
    if (dwNameSize == 0 || dwDomainSize == 0)
    {
        printf("LookupAccountSidW failed (%d)\n", GetLastError());
        retValue = 1;
        goto Exit;
    }
    // Allocate memory for name and domain
    lpName = (LPWSTR)LocalAlloc(0, dwNameSize * sizeof(WCHAR));
    lpDomain = (LPWSTR)LocalAlloc(0, dwDomainSize * sizeof(WCHAR));

    if (!lpName || !lpDomain)
    {
        printf("Memory allocation failed\n");
        retValue = 1;
        goto Exit;
    }

    // Second call to LookupAccountSid to get the account name
    if (!LookupAccountSidW(NULL, pUserSid, lpName, &dwNameSize, lpDomain, &dwDomainSize, &eSidType))
    {
        printf("LookupAccountSidW failed (%d)\n", GetLastError());
        retValue = 1;
        goto Exit;
    }

    // 
    // put together the username and domain into a string
    //
    dwSize = wcslen(lpName) + wcslen(lpDomain) + 2;
    //
    // Allocate memory for the string
    //
    *pStringSid = (LPWSTR)LocalAlloc(0, dwSize * sizeof(WCHAR));
    //
    // put together the username and domain into a string
    //
    wsprintf(*pStringSid, L"%s\\%s", lpDomain, lpName);


Exit:
    if (processTokenUser != NULL)
    {
        LocalFree(processTokenUser);
    }
    if (lpName != NULL)
    {
        LocalFree(lpName);
    }
    if (lpDomain != NULL)
    {
        LocalFree(lpDomain);
    }
    return retValue;
}

extern "C" void TokenImpersonationCheck()
{
    TraceLoggingRegister(g_hJonMon);
    //
    // Loop every 60s to use message box
    //
    while (true)
    {
        //
        // Get snapshot of all threads
        //
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE)
        {
            printf("CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
            return;
        }

        //
        // for each thread attempt to get access token and print handle
        //
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hThreadSnap, &te32))
        {
            printf("Thread32First failed (%d)\n", GetLastError());
            CloseHandle(hThreadSnap);
            return;
        }
        do
        {
            //
            // OpenThread with THREAD_QUERY_INFORMATION access right
            //
            HANDLE hThread = NULL;
            HANDLE hToken = NULL;
            HANDLE processToken = NULL;
            HANDLE pHandle = NULL;
            DWORD retValue = 0;
            TOKEN_STATISTICS tokenStats;
            DWORD dwReturnLength;
            LPWSTR threadTokenUser = NULL;
            LPWSTR processTokenUser = NULL;
            PDWORD threadIntegrityLevel = 0;
            PDWORD processIntegrityLevel = 0;
            SYSTEMTIME st;
            BOOL result;
            REGHANDLE RegistrationHandle = NULL;

            hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
            if (hThread == NULL)
            {
                goto Exit;
            }

            //
            // Get thread access token
            //
            if (!OpenThreadToken(hThread, TOKEN_QUERY, FALSE, &hToken))
            {
                goto Exit;
            }

            retValue = IntegritySID(hToken, &threadIntegrityLevel);
            if (retValue != 0)
            {
                goto Exit;
            }


            if (!GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(TOKEN_STATISTICS), &dwReturnLength))
            {
                printf("GetTokenInformation failed (%d)\n", GetLastError());
                goto Exit;
            }


            retValue = TokenUserName(hToken, &threadTokenUser);
            if (retValue != 0 || threadTokenUser == NULL)
            {
                goto Exit;
            }
            //
            // Print token handle and impersonation level
            //
            if (tokenStats.ImpersonationLevel != SecurityImpersonation && tokenStats.ImpersonationLevel != SecurityDelegation)
            {
                goto Exit;
            }
            pHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, te32.th32OwnerProcessID);
            if (pHandle == NULL) {
                printf("OpenProcess failed (%d), ProcessID: %d\n", GetLastError(), te32.th32OwnerProcessID);
                goto Exit;
            }
            result = OpenProcessToken(pHandle, TOKEN_QUERY, &processToken);
            if (processToken == NULL) {
                printf("OpenProcessToken failed (%d) ProcessId: %d\n", GetLastError(), te32.th32OwnerProcessID);
                goto Exit;
            }

            retValue = IntegritySID(processToken, &processIntegrityLevel);
            if (retValue != 0)
            {
                printf("IntegritySID failed (%d)\n", GetLastError());
                goto Exit;
            }

            retValue = TokenUserName(processToken, &processTokenUser);
            if (retValue != 0 || processTokenUser == NULL)
            {
                goto Exit;
            }

            if ((*processIntegrityLevel != 16384) && (wcscmp(processTokenUser, threadTokenUser) != 0))
            {

                
                GetSystemTime(&st);

                TraceLoggingWrite(
                    g_hJonMon,
                    "16",
                    TraceLoggingInt32(16, "EventID"),
                    TraceLoggingUInt32(te32.th32ThreadID, "ThreadID"),
                    TraceLoggingUInt32(te32.th32OwnerProcessID, "ProcessID"),
                    TraceLoggingUInt32(*threadIntegrityLevel, "ThreadIntegrityLevel"),
                    TraceLoggingSystemTime(st, "EventTime"),
                    TraceLoggingWideString(threadTokenUser, "ImpersonatedUser")
                );
            }


        Exit:
            if (threadTokenUser != NULL)
            {
                LocalFree(threadTokenUser);
                threadTokenUser = NULL;
            }
            if (processTokenUser != NULL)
            {
                LocalFree(processTokenUser);
                processTokenUser = NULL;
            }
            if (hThread != NULL)
            {
                CloseHandle(hThread);
                hThread = NULL;
            }
            if (hToken != NULL)
            {
                CloseHandle(hToken);
                hToken = NULL;
            }
            if (pHandle != NULL)
            {
                CloseHandle(pHandle);
                pHandle = NULL;
            }
            if (processToken != NULL)
            {
                CloseHandle(processToken);
                processToken = NULL;
            }



        } while (Thread32Next(hThreadSnap, &te32));

        CloseHandle(hThreadSnap);

        Sleep(5000);
    }

}

