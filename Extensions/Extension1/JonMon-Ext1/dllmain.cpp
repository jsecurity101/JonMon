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

DWORD IntegritySID(HANDLE hToken, std::wstring *IntegrityLevel) {

    PSID pIntegritySid = NULL;
    PTOKEN_MANDATORY_LABEL pIntegrityLabel = NULL;
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

    // Get the TOKEN_MANDATORY_LABEL structure
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

    //ConvertSidToStringSidW(pIntegritySid, pStringSid);

    //
    // switch statement to determine integrity level
    //
    switch (*GetSidSubAuthority(pIntegritySid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pIntegritySid) - 1)))
    {
        case SECURITY_MANDATORY_UNTRUSTED_RID:
        {
            *IntegrityLevel = L"UNTRUSTED";
            break;
        }
        case SECURITY_MANDATORY_LOW_RID:
        {
            *IntegrityLevel = L"LOW";
            break;
        }
        case SECURITY_MANDATORY_MEDIUM_RID:
        {
            *IntegrityLevel = L"MEDIUM";
			break;
		}  
        case SECURITY_MANDATORY_HIGH_RID:
        {
            *IntegrityLevel = L"HIGH";
            break;
        }
        case SECURITY_MANDATORY_SYSTEM_RID:
        {
            *IntegrityLevel = L"SYSTEM";
            break;
        }
        default:
        {
            *IntegrityLevel = L"UNKNOWN";
            break;
        }
    }

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
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwTokenInfoSize = 0;
    LPWSTR lpName = NULL;
    LPWSTR lpDomain = NULL;
    DWORD dwNameSize = 0;
    DWORD dwDomainSize = 0;
    SID_NAME_USE eSidType;
    PSID pUserSid = NULL;
    DWORD dwSize = 0;
    //
    // pull thread tokens user
    //

    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenInfoSize);

    if (dwTokenInfoSize == 0)
    {
        printf("GetTokenInformation failed (%d)\n", GetLastError());
        retValue = 1;
        goto Exit;
    }

    // Allocate memory for the TOKEN_USER structure
    pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwTokenInfoSize);
    if (pTokenUser == NULL)
    {
        printf("Memory allocation failed\n");
        retValue = 1;
        goto Exit;
    }

    // Get the TOKEN_USER structure
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoSize, &dwTokenInfoSize))
    {
        printf("GetTokenInformation failed (%d)\n", GetLastError());
        retValue = 1;
        goto Exit;
    }

    // Extract the user SID from the TOKEN_USER structure
    pUserSid = pTokenUser->User.Sid;

    //
    // Convert SID to actual username
    //


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
    if (pTokenUser != NULL)
    {
        LocalFree(pTokenUser);
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
            HANDLE pToken = NULL;
            HANDLE pHandle = NULL;
            DWORD retValue = 0;
            TOKEN_STATISTICS tokenStats;
            DWORD dwReturnLength;
            LPWSTR uTokenUser = NULL;
            LPWSTR pTokenUser = NULL;
            std::wstring tIntegrityLevel;
            std::wstring prIntegrityLevel;
            SYSTEMTIME filetime;
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
                //printf("OpenThreadToken failed (%d)\n", GetLastError());
                goto Exit;
            }

            retValue = IntegritySID(hToken, &tIntegrityLevel);
            if (retValue != 0)
            {
                goto Exit;
            }
            if (!GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(TOKEN_STATISTICS), &dwReturnLength))
            {
                printf("GetTokenInformation failed (%d)\n", GetLastError());
                goto Exit;
            }


            retValue = TokenUserName(hToken, &uTokenUser);
            if (retValue != 0 || uTokenUser == NULL)
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
            result = OpenProcessToken(pHandle, TOKEN_QUERY, &pToken);
            if (pToken == NULL) {
                printf("OpenProcessToken failed (%d) ProcessId: %d\n", GetLastError(), te32.th32OwnerProcessID);
                goto Exit;
            }

            retValue = IntegritySID(pToken, &prIntegrityLevel);
            if (retValue != 0)
            {
                printf("IntegritySID failed (%d)\n", GetLastError());
                goto Exit;
            }

            retValue = TokenUserName(pToken, &pTokenUser);
            if (retValue != 0 || pTokenUser == NULL)
            {
                goto Exit;
            }

            if ((prIntegrityLevel != L"SYSTEM") && (wcscmp(pTokenUser, uTokenUser) != 0)) {

                FILETIME st;
                GetSystemTimeAsFileTime(&st);

                EventRegister(&JonMonProvider,
                    NULL,
                    NULL,
                    &RegistrationHandle
                );
                EVENT_DATA_DESCRIPTOR EventData[7];
                //
                //Write events
                //
                EventDataDescCreate(&EventData[0], &st, sizeof(st));
                EventDataDescCreate(&EventData[1], &te32.th32OwnerProcessID, sizeof(DWORD));
                EventDataDescCreate(&EventData[2], &te32.th32ThreadID, sizeof(DWORD));
                EventDataDescCreate(&EventData[3], uTokenUser, (wcslen(uTokenUser) + 1) * sizeof(WCHAR));
                EventDataDescCreate(&EventData[4], tIntegrityLevel.c_str(), (wcslen(tIntegrityLevel.c_str()) + 1) * sizeof(WCHAR));
                EventDataDescCreate(&EventData[5], pTokenUser, (wcslen(pTokenUser) + 1) * sizeof(WCHAR));
                EventDataDescCreate(&EventData[6], prIntegrityLevel.c_str(), (wcslen(prIntegrityLevel.c_str()) + 1) * sizeof(WCHAR));
                EventWrite(RegistrationHandle, &ThreadTokenImpersonation, 7, EventData);
                EventUnregister(RegistrationHandle);
                CloseHandle(&RegistrationHandle);
           }


        Exit:
            if (uTokenUser != NULL)
            {
                LocalFree(uTokenUser);
            }
            if (pTokenUser != NULL)
            {
                LocalFree(pTokenUser);
            }
            if (hThread != NULL)
            {
                CloseHandle(hThread);
            }
            if (hToken != NULL)
            {
                CloseHandle(hToken);
            }
            if (pHandle != NULL)
            {
                CloseHandle(pHandle);
            }
            if (pToken != NULL)
            {
                CloseHandle(pToken);
            }


        } while (Thread32Next(hThreadSnap, &te32));

        CloseHandle(hThreadSnap);

        Sleep(5000);
    }

}

