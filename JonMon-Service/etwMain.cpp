#include <ws2tcpip.h>
#include <Windows.h>
#include <sstream>
#include <evntrace.h>
#include <vector>
#include <stdio.h>
#include <DbgHelp.h>

#include "global.h"
#include "context.h"
#include "etwMain.h"
#include <thread>
#include <vector>
#include "tlhelp32.h"
#include <tdh.h>


#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "dbghelp.lib")

DWORD lsassPID = 0;

//
// Used to process ETW event properties. Plan to remove these and move to TDH functions in the future.
//
template<typename Type>
inline auto GetData(byte*& data) {
    auto value{ reinterpret_cast<Type*>(data) };
    data += sizeof(*value);
    return value;
}

inline auto GetWideString(byte*& data) {
    auto wideString{ reinterpret_cast<WCHAR*>(data) };
    data += (wcslen(wideString) + 1) * sizeof(WCHAR);
    return wideString;
}

int StopETWTrace() {
    TRACEHANDLE traceHandle = 0;
    ULONG status, bufferSize;
    wchar_t traceName[] = L"JonMon";

    EVENT_TRACE_PROPERTIES* traceProp;
    bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(traceName) + sizeof(WCHAR);
    traceProp = (EVENT_TRACE_PROPERTIES*)LocalAlloc(LPTR, bufferSize);
    traceProp->Wnode.BufferSize = bufferSize;
    traceProp->Wnode.Guid = JonMonGuid;
    traceProp->LogFileNameOffset = 0;
    traceProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    status = StopTrace(traceHandle, traceName, traceProp);

    if (status != ERROR_SUCCESS) {
        OutputDebugStringW(L"StopTrace Failed");
        return status;
    }
    else {
        OutputDebugStringW(L"StopTrace Success");
        return status;
    }

    return 0;

}

DWORD ProtectionCheck()
{
    DWORD protectionLevel = 0;
    do {
        PROCESS_PROTECTION_LEVEL_INFORMATION protectionInfo = { 0 };
        if (GetProcessInformation(GetCurrentProcess(), ProcessProtectionLevelInfo, &protectionInfo, sizeof(protectionInfo))) {
            if (protectionInfo.ProtectionLevel != 5) {
                protectionLevel = 1;
            }
        }
        else {
            printf("Failed to retrieve PPL. Error code: %lu\n", GetLastError());
            return 1;
        }
    } while (protectionLevel == 0);
    return 0;
}

void ChangePPL() {

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

DWORD CheckLSASSPID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    LPCWSTR processName = L"";
    DWORD PID = 0;

    if (Process32First(snapshot, &processEntry)) {
        while (_wcsicmp(processName, L"lsass.exe") != 0) {
            Process32Next(snapshot, &processEntry);
            processName = processEntry.szExeFile;
            PID = processEntry.th32ProcessID;

        }
        return PID;

    }
    CloseHandle(snapshot);
}

int TraceEvent() {
    //
    // Changing PPL level
    //
    ChangePPL();

    //
    // check to see if current process is protected
    //
    DWORD retValue = ProtectionCheck();
    if (retValue != 0) {
        printf("Process is not protected\n");
        ChangePPL();
    }
    lsassPID = CheckLSASSPID();
    const char name[] = "JonMon";
    TRACEHANDLE hTrace = 0;
    ULONG result, bufferSize;
    EVENT_TRACE_LOGFILEA trace;
    EVENT_TRACE_PROPERTIES* traceProp;

    memset(&trace, 0, sizeof(EVENT_TRACE_LOGFILEA));
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.LoggerName = (LPSTR)name;
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)ProcessEvent;

    bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(name) + sizeof(WCHAR);

    traceProp = (EVENT_TRACE_PROPERTIES*)LocalAlloc(LPTR, bufferSize);
    traceProp->Wnode.BufferSize = bufferSize;
    traceProp->Wnode.ClientContext = 2;
    traceProp->Wnode.Guid = JonMonGuid;
    traceProp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    traceProp->LogFileNameOffset = 0;
    traceProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    if ((result = StartTraceA(&hTrace, (LPCSTR)name, traceProp)) != ERROR_SUCCESS) {
        OutputDebugStringW(L"Error starting trace\n");
        return GetLastError();
    }

    ENABLE_TRACE_PARAMETERS enableTraceParameters;
    ZeroMemory(&enableTraceParameters, sizeof(ENABLE_TRACE_PARAMETERS));

    enableTraceParameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    enableTraceParameters.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;

    OutputDebugString(L"[+] JonMon Trace started\n");

    //RPC Events
    if ((result = EnableTraceEx2(
        hTrace,
        &RPC,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        &enableTraceParameters
    )) != ERROR_SUCCESS) {
        OutputDebugString(L"[!] Error EnableTraceEx - RPC\n");
    }

    //Threat Intel
    if ((result = EnableTraceEx2(
        hTrace,
        &ThreatIntel,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        &enableTraceParameters
    )) != ERROR_SUCCESS) {
        OutputDebugString(L"[!] Error EnableTraceEx - Threat Intel\n");
    }

    //WMI Events
    if ((result = EnableTraceEx2(
        hTrace,
        &WMIActivty,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        &enableTraceParameters
    )) != ERROR_SUCCESS) {
        OutputDebugString(L"[!] Error EnableTraceEx - WMI\n");
    }

    //DotNet Events
    if ((result = EnableTraceEx2(
        hTrace,
        &DotNet,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x8,
        0,
        0,
        NULL
    )) != ERROR_SUCCESS) {
        OutputDebugString(L"[!] Error EnableTraceEx - DotNet\n");
    }

    //Network Events
    if ((result = EnableTraceEx(
        &Network,
        nullptr,
        hTrace,
        TRUE,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    )) != ERROR_SUCCESS) {
        OutputDebugString(L"[!] Error EnableTraceEx - Network\n");
    }

    //Task Scheduler Events
    if ((result = EnableTraceEx(
        &TaskSched,
        nullptr,
        hTrace,
        TRUE,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    )) != ERROR_SUCCESS) {
        OutputDebugString(L"[!] Error EnableTraceEx - TaskSched\n");
    }

    //AMSI Events
    if ((result = EnableTraceEx(
        &AMSI,
        nullptr,
        hTrace,
        TRUE,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    )) != ERROR_SUCCESS) {
        OutputDebugString(L"[!] Error EnableTraceEx - AMSI\n");
    }

    if ((result = EnableTraceEx(
        &DPAPI,
        nullptr,
        hTrace,
        TRUE,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    )) != ERROR_SUCCESS) {
        OutputDebugString(L"[!] Error EnableTraceEx - DPAPI\n");
    }

    hTrace = OpenTraceA(&trace);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        OutputDebugString(L"[!] Error OpenTrace\n");
        return 1;
    }

    result = ProcessTrace(&hTrace, 1, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] Error ProcessTrace\n");
        return 1;
    }
}

/*
* -----------------------------
* Event Processessing Functions
* -----------------------------
*/

void ProcessEvent(
    _In_ PEVENT_RECORD EventRecord
) {
    PEVENT_HEADER eventHeader = &EventRecord->EventHeader;
    PEVENT_DESCRIPTOR eventDescriptor = &eventHeader->EventDescriptor;
    NTSTATUS status;

    if (eventHeader->ProviderId == ThreatIntel) {
        status = WriteThreatIntelEvents(EventRecord, eventHeader);
    }
    if (eventHeader->ProviderId == RPC) {
        switch (eventDescriptor->Id) {
        case 5:
        {
            auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
            BOOL result = RpcEvent(EventRecord, eventHeader, RPCClientCall);

            break;
        }
        case 6:
        {
            auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
            BOOL result = RpcEvent(EventRecord, eventHeader, RPCServerCall);
            break;
        }
        default: {
            break;
        }

        }
    }
    if (eventHeader->ProviderId == Network) {
        switch (eventDescriptor->Id) {
        case 10:
        {
            auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
            const wchar_t* Initiated = L"True";
            BOOL result = WriteNetworkEvents(EventRecord, eventHeader, (wchar_t*)Initiated);
            break;
        }
        case 11:
        {
            const wchar_t* Initiated = L"False";
            auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
            BOOL result = WriteNetworkEvents(EventRecord, eventHeader, (wchar_t*)Initiated);
            break;
        }
        default: {
            break;
        }

        }
    }
    if (eventHeader->ProviderId == DotNet) {
        switch (eventDescriptor->Id) {
        case 154: {
            auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
            //printf("DotNet AssemblyLoad Event from PID %d\n", eventHeader->ProcessId);
            WriteDotNetEvents(EventRecord, eventHeader);
        }

        default: {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == AMSI) {
        BOOL res = WriteAMSIEvents(EventRecord, eventHeader);

    }
    if (eventHeader->ProviderId == TaskSched) {
        BOOL res = WriteTaskSchedEvents(EventRecord, eventHeader);
    }
    if (eventHeader->ProviderId == WMIActivty) {
        BOOL res = WriteWMIEvents(EventRecord, eventHeader);
    }
    if (eventHeader->ProviderId == DPAPI) {
        BOOL res = DPAPIEvents(EventRecord, eventHeader);
    }
}

NTSTATUS WriteETWEvents(
    _In_ PEVENT_DATA_DESCRIPTOR eventData,
    _In_ EVENT_DESCRIPTOR eventDescriptor,
    _In_ int metaDataSize
) {
    REGHANDLE RegistrationHandle = NULL;
    NTSTATUS status = EventRegister(
        &JonMonGuid,
        NULL,
        NULL,
        &RegistrationHandle
    );
    if (status != ERROR_SUCCESS)
    {
        return status;
    }
    status = EventWrite(
        RegistrationHandle,
        &eventDescriptor,
        metaDataSize,
        eventData
    );
    if (status != ERROR_SUCCESS)
    {
        EventUnregister(RegistrationHandle);
        return status;
    }

    //CleanUp
    EventUnregister(RegistrationHandle);
}

NTSTATUS WriteThreatIntelEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    PEVENT_HEADER eventHeader = &EventRecord->EventHeader;
    PEVENT_HEADER_EXTENDED_DATA_ITEM extendedData = EventRecord->ExtendedData;
    PEVENT_DESCRIPTOR eventDescriptor = &eventHeader->EventDescriptor;
    NTSTATUS status = ERROR_SUCCESS;
    REGHANDLE RegistrationHandle = NULL;
    HANDLE hProcess = GetCurrentProcess();
    wchar_t* sourceImagePath = nullptr;
    wchar_t* targetImagePath = nullptr;
    std::wstring ImagePath_str;
    std::wstring targetImagePath_str;
    wchar_t* CallStack = nullptr;
    static UINT32 prevCallingProcessId = 0;
    static UINT32 prevTargetProcessId = 0;
    switch (eventHeader->EventDescriptor.Id) {
    case 1:
    {
       auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
       auto CallingProcessId{ GetData<UINT32>(data) };
       auto CallingProcessCreationTime{ GetData<FILETIME>(data) };
       auto CallingProcessStartKey{ GetData<UINT64>(data) };
       auto CallingProcessSignatureLevel{ GetData<UINT8>(data) };
       auto CallingProcessSectionSignatureLevel{ GetData<UINT8>(data) };
       auto CallingProcessProtection{ GetData<UINT8>(data) };
       auto CallingThreadId{ GetData<UINT32>(data) };
       auto CallingThreadCreationTime{ GetData<FILETIME>(data) };
       auto TargetProcessId{ GetData<UINT32>(data) };
       auto TargetProcessCreateTime{ GetData<FILETIME>(data) };
       auto TargetProcessStartKey{ GetData<UINT64>(data) };
       auto TargetProcessSignatureLevel{ GetData<UINT8>(data) };
       auto TargetProcessSectionSignatureLevel{ GetData<UINT8>(data) };
       auto TargetProcessProtection{ GetData<UINT8>(data) };
       auto OriginalProcessId{ GetData<UINT32>(data) };
       auto OriginalProcessCreateTime{ GetData<FILETIME>(data) };
       auto OriginalProcessStartKey{ GetData<UINT64>(data) };
       auto OriginalProcessSignatureLevel{ GetData<UINT8>(data) };
       auto OriginalProcessProtection{ GetData<UINT8>(data) };
       auto BaseAddress{ GetData<UINT64>(data) };

        if (*CallingProcessId == *TargetProcessId) {
            goto Exit;
        }

        if (GetImagePath(*CallingProcessId, &sourceImagePath) != ERROR_SUCCESS) {
            ImagePath_str = L"Unknown";
        }
        else {
            ImagePath_str = sourceImagePath;
        }
        if (GetImagePath(*TargetProcessId, &targetImagePath) != ERROR_SUCCESS) {
            targetImagePath_str = L"Unknown";
        }
        else {
            targetImagePath_str = targetImagePath;
        }

        CallStack = GetCallStack(EventRecord, extendedData, hProcess);
        
        FILETIME st;
        GetSystemTimeAsFileTime(&st);

        EVENT_DATA_DESCRIPTOR EventData[11];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], CallingThreadId, 4);
        EventDataDescCreate(&EventData[2], CallingProcessId, 4);
        EventDataDescCreate(&EventData[3], TargetProcessId, 4);
        EventDataDescCreate(&EventData[4], CallingProcessStartKey, 8);
        EventDataDescCreate(&EventData[5], TargetProcessStartKey, 8);
        EventDataDescCreate(&EventData[6], OriginalProcessId, 4);
        EventDataDescCreate(&EventData[7], BaseAddress, sizeof(BaseAddress));
        EventDataDescCreate(&EventData[8], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[9], targetImagePath_str.c_str(), (wcslen(targetImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[10], CallStack, (wcslen(CallStack) + 1) * sizeof(WCHAR));



        status = WriteETWEvents(EventData, TIRemoteAllocateVirtualMemory, 11);
        goto Exit;
    }
    case 4:
    {

        FILETIME st;
        GetSystemTimeAsFileTime(&st);

        PTRACE_EVENT_INFO pInfo = NULL;
        DWORD bufferSize = 0;

        UINT32 CallingThreadId, CallingProcessId, TargetProcessId, OriginalProcessId, TargetThreadId;
        UINT64 CallingProcessStartKey, TargetProcessStartKey, ApcRoutine, ApcArgument1;
        DWORD status = ERROR_SUCCESS;

        //
        // Testing out TDH APIs
        //

        status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        if (ERROR_INSUFFICIENT_BUFFER == status) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (pInfo == NULL) {
                // Handle allocation failure
                OutputDebugString(L"[!] Error allocating memory for event info\n");
                goto Exit;
            }

            // Get the event info
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }

        if (ERROR_SUCCESS != status) {
            // Handle error (could not obtain event info)
            free(pInfo);
            OutputDebugString(L"[!] Error getting event info\n");
            goto Exit;
        }
        for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            PROPERTY_DATA_DESCRIPTOR dataDescriptor;
            DWORD propertySize = 0;
            WCHAR* propertyName = (WCHAR*)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);

            dataDescriptor.PropertyName = (ULONGLONG)propertyName;
            dataDescriptor.ArrayIndex = ULONG_MAX;

            // Determine the size of the property
            status = TdhGetPropertySize(EventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
            if (status != ERROR_SUCCESS) {
                // Handle error
                wprintf(L"Error getting size for property %ls\n", propertyName);
                continue;
            }

            BYTE* propertyData = (BYTE*)malloc(propertySize);
            if (!propertyData) {
                // Handle allocation failure
                wprintf(L"Error allocating memory for property %ls\n", propertyName);
                continue;
            }

            // Get the property data
            status = TdhGetProperty(EventRecord, 0, NULL, 1, &dataDescriptor, propertySize, propertyData);
            if (status != ERROR_SUCCESS) {
                // Handle error
                wprintf(L"Error getting data for property %ls\n", propertyName);
                free(propertyData);
                continue;
            }
            switch (i) {
            case 0:
            {
                CallingProcessId = *(UINT32*)propertyData;
                break;
            }
            case 2:
            {
                CallingProcessStartKey = *(UINT64*)propertyData;
                break;
            }
            case 6:
            {
                CallingThreadId = *(UINT32*)propertyData;
                break;
            }
            case 8:
            {
                TargetProcessId = *(UINT32*)propertyData;
                break;
            }
            case 10:
            {
                TargetProcessStartKey = *(UINT64*)propertyData;
                break;
            }
            case 14:
            {
                TargetThreadId = *(UINT32*)propertyData;
            }
            case 16:
            {
                OriginalProcessId = *(UINT32*)propertyData;
                break;
            }
            case 21:
            {
                ApcRoutine = *(UINT64*)propertyData;
                break;
            }
            case 22:
            {
                ApcArgument1 = *(UINT64*)propertyData;
                break;
            }
            default:
            {
                break;
            }
            }
            free(propertyData);

        }

        if (GetImagePath(CallingProcessId, &sourceImagePath) != ERROR_SUCCESS) {
            ImagePath_str = L"Unknown";
        }
        else {
            ImagePath_str = sourceImagePath;
        }
        if (GetImagePath(TargetProcessId, &targetImagePath) != ERROR_SUCCESS) {
            targetImagePath_str = L"Unknown";
        }
        else {
            targetImagePath_str = targetImagePath;
        }

        CallStack = GetCallStack(EventRecord, extendedData, hProcess);

        EVENT_DATA_DESCRIPTOR EventData[13];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], &CallingThreadId, 4);
        EventDataDescCreate(&EventData[2], &CallingProcessId, 4);
        EventDataDescCreate(&EventData[3], &TargetProcessId, 4);
        EventDataDescCreate(&EventData[4], &TargetThreadId, 4);
        EventDataDescCreate(&EventData[5], &CallingProcessStartKey, 8);
        EventDataDescCreate(&EventData[6], &TargetProcessStartKey, 8);
        EventDataDescCreate(&EventData[7], &OriginalProcessId, 4);
        EventDataDescCreate(&EventData[8], &ApcRoutine, sizeof(ApcRoutine));
        EventDataDescCreate(&EventData[9], &ApcArgument1, sizeof(ApcArgument1));
        EventDataDescCreate(&EventData[10], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[11], targetImagePath_str.c_str(), (wcslen(targetImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[12], CallStack, (wcslen(CallStack) + 1) * sizeof(WCHAR));


        status = WriteETWEvents(EventData, TIQueueUserAPCEvent, 13);
        goto Exit;
    }
    case 6:
    {
        auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
        auto CallingProcessId{ GetData<UINT32>(data) };
        auto CallingProcessCreationTime{ GetData<FILETIME>(data) };
        auto CallingProcessStartKey{ GetData<UINT64>(data) };
        auto CallingProcessSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessSectionSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessProtection{ GetData<UINT8>(data) };
        auto CallingThreadId{ GetData<UINT32>(data) };
        auto CallingThreadCreationTime{ GetData<FILETIME>(data) };
        auto TargetProcessId{ GetData<UINT32>(data) };
        auto TargetProcessCreateTime{ GetData<FILETIME>(data) };
        auto TargetProcessStartKey{ GetData<UINT64>(data) };
        auto TargetProcessSignatureLevel{ GetData<UINT8>(data) };
        auto TargetProcessSectionSignatureLevel{ GetData<UINT8>(data) };
        auto TargetProcessProtection{ GetData<UINT8>(data) };
        auto OriginalProcessId{ GetData<UINT32>(data) };
        auto OriginalProcessCreateTime{ GetData<FILETIME>(data) };
        auto OriginalProcessStartKey{ GetData<UINT64>(data) };
        auto OriginalProcessSignatureLevel{ GetData<UINT8>(data) };
        auto OriginalProcessProtection{ GetData<UINT8>(data) };
        auto BaseAddress{ GetData<UINT64>(data) };

        if (*CallingProcessId == *TargetProcessId) {
            goto Exit;
        }

        if (GetImagePath(*CallingProcessId, &sourceImagePath) != ERROR_SUCCESS) {
            ImagePath_str = L"Unknown";
        }
        else {
            ImagePath_str = sourceImagePath;
        }
        if (GetImagePath(*TargetProcessId, &targetImagePath) != ERROR_SUCCESS) {
            targetImagePath_str = L"Unknown";
        }
        else {
            targetImagePath_str = targetImagePath;
        }

        CallStack = GetCallStack(EventRecord, extendedData, hProcess);

        FILETIME st;
        GetSystemTimeAsFileTime(&st);


        EVENT_DATA_DESCRIPTOR EventData[11];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], CallingThreadId, 4);
        EventDataDescCreate(&EventData[2], CallingProcessId, 4);
        EventDataDescCreate(&EventData[3], TargetProcessId, 4);
        EventDataDescCreate(&EventData[4], CallingProcessStartKey, 8);
        EventDataDescCreate(&EventData[5], TargetProcessStartKey, 8);
        EventDataDescCreate(&EventData[6], OriginalProcessId, 4);
        EventDataDescCreate(&EventData[7], BaseAddress, sizeof(BaseAddress));
        EventDataDescCreate(&EventData[8], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[9], targetImagePath_str.c_str(), (wcslen(targetImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[10], CallStack, (wcslen(CallStack) + 1) * sizeof(WCHAR));



        status = WriteETWEvents(EventData, TIRemoteAllocateVirtualMemory, 11);
		goto Exit;
	}
    case 13:
    {
        auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
        auto OperationStatus{ GetData<UINT32>(data) };
        auto CallingProcessId{ GetData<UINT32>(data) };
        auto CallingProcessCreationTime{ GetData<FILETIME>(data) };
        auto CallingProcessStartKey{ GetData<UINT64>(data) };
        auto CallingProcessSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessSectionSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessProtection{ GetData<UINT8>(data) };
        auto CallingThreadId{ GetData<UINT32>(data) };
        auto CallingThreadCreationTime{ GetData<FILETIME>(data) };
        auto TargetProcessId{ GetData<UINT32>(data) };
        auto TargetProcessCreationTime{ GetData<FILETIME>(data) };
        auto TargetProcessStartKey{ GetData<UINT64>(data) };

        FILETIME st;
        GetSystemTimeAsFileTime(&st);

        CallStack = GetCallStack(EventRecord, extendedData, hProcess);

        //
        //Getting ImagePath
        //
        if (GetImagePath(*CallingProcessId, &sourceImagePath) != ERROR_SUCCESS) {
            ImagePath_str = L"Unknown";
        }
        else {
            ImagePath_str = sourceImagePath;
        }

        //
        //Put C:\Windows\System32\lsass.exe in a variable
        //
        std::wstring lsassPath = L"C:\\Windows\\System32\\lsass.exe";

        EVENT_DATA_DESCRIPTOR EventData[9];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], CallingProcessId, 4);
        EventDataDescCreate(&EventData[2], CallingThreadId, 4);
        EventDataDescCreate(&EventData[3], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[4], TargetProcessId, 4);
        EventDataDescCreate(&EventData[5], lsassPath.c_str(), (wcslen(lsassPath.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[6], CallingProcessStartKey, sizeof(CallingProcessStartKey));
        EventDataDescCreate(&EventData[7], TargetProcessStartKey, sizeof(TargetProcessStartKey));
        EventDataDescCreate(&EventData[8], CallStack, (wcslen(CallStack) + 1) * sizeof(WCHAR));

        NTSTATUS status = WriteETWEvents(EventData, TIReadProcessMemory, 9);

        goto Exit;
    }
    case 14:
    {
        auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
        auto OperationStatus{ GetData<UINT32>(data) };
        auto CallingProcessId{ GetData<UINT32>(data) };
        auto CallingProcessCreationTime{ GetData<FILETIME>(data) };
        auto CallingProcessStartKey{ GetData<UINT64>(data) };
        auto CallingProcessSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessSectionSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessProtection{ GetData<UINT8>(data) };
        auto CallingThreadId{ GetData<UINT32>(data) };
        auto CallingThreadCreationTime{ GetData<FILETIME>(data) };
        auto TargetProcessId{ GetData<UINT32>(data) };
        auto TargetProcessCreationTime{ GetData<FILETIME>(data) };
        auto TargetProcessStartKey{ GetData<UINT64>(data) };

        FILETIME st;
        GetSystemTimeAsFileTime(&st);

        CallStack = GetCallStack(EventRecord, extendedData, hProcess);

        if (GetImagePath(*CallingProcessId, &sourceImagePath) != ERROR_SUCCESS) {
            ImagePath_str = L"Unknown";
        }
        else {
            ImagePath_str = sourceImagePath;
        }

        if (GetImagePath(*TargetProcessId, &targetImagePath) != ERROR_SUCCESS) {
            targetImagePath_str = L"Unknown";
        }
        else {
            targetImagePath_str = targetImagePath;
        }

        EVENT_DATA_DESCRIPTOR EventData[9];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], CallingProcessId, 4);
        EventDataDescCreate(&EventData[2], CallingThreadId, 4);
        EventDataDescCreate(&EventData[3], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[4], TargetProcessId, 4);
        EventDataDescCreate(&EventData[5], targetImagePath_str.c_str(), (wcslen(targetImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[6], CallingProcessStartKey, sizeof(CallingProcessStartKey));
        EventDataDescCreate(&EventData[7], TargetProcessStartKey, sizeof(TargetProcessStartKey));
        EventDataDescCreate(&EventData[8], CallStack, (wcslen(CallStack) + 1) * sizeof(WCHAR));
        NTSTATUS status = WriteETWEvents(EventData, TIWriteProcessMemory, 9);
        goto Exit;
    }
    case 21:
    {
        auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
        auto CallingProcessId{ GetData<UINT32>(data) };
        auto CallingProcessCreationTime{ GetData<FILETIME>(data) };
        auto CallingProcessStartKey{ GetData<UINT64>(data) };
        auto CallingProcessSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessSectionSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessProtection{ GetData<UINT8>(data) };
        auto CallingThreadId{ GetData<UINT32>(data) };
        auto CallingThreadCreationTime{ GetData<FILETIME>(data) };
        auto TargetProcessId{ GetData<UINT32>(data) };
        auto TargetProcessCreateTime{ GetData<FILETIME>(data) };
        auto TargetProcessStartKey{ GetData<UINT64>(data) };
        auto TargetProcessSignatureLevel{ GetData<UINT8>(data) };
        auto TargetProcessSectionSignatureLevel{ GetData<UINT8>(data) };
        auto TargetProcessProtection{ GetData<UINT8>(data) };
        auto OriginalProcessId{ GetData<UINT32>(data) };
        auto OriginalProcessCreateTime{ GetData<FILETIME>(data) };
        auto OriginalProcessStartKey{ GetData<UINT64>(data) };
        auto OriginalProcessSignatureLevel{ GetData<UINT8>(data) };
        auto OriginalProcessProtection{ GetData<UINT8>(data) };
        auto BaseAddress{ GetData<UINT64>(data) };

        if (*CallingProcessId == *TargetProcessId) {
            goto Exit;
        }

        if (GetImagePath(*CallingProcessId, &sourceImagePath) != ERROR_SUCCESS) {
            ImagePath_str = L"Unknown";
        }
        else {
            ImagePath_str = sourceImagePath;
        }
        if (GetImagePath(*TargetProcessId, &targetImagePath) != ERROR_SUCCESS) {
            targetImagePath_str = L"Unknown";
        }
        else {
            targetImagePath_str = targetImagePath;
        }

        CallStack = GetCallStack(EventRecord, extendedData, hProcess);
        FILETIME st;
        GetSystemTimeAsFileTime(&st);
        EVENT_DATA_DESCRIPTOR EventData[11];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], CallingThreadId, 4);
        EventDataDescCreate(&EventData[2], CallingProcessId, 4);
        EventDataDescCreate(&EventData[3], TargetProcessId, 4);
        EventDataDescCreate(&EventData[4], CallingProcessStartKey, 8);
        EventDataDescCreate(&EventData[5], TargetProcessStartKey, 8);
        EventDataDescCreate(&EventData[6], OriginalProcessId, 4);
        EventDataDescCreate(&EventData[7], BaseAddress, sizeof(BaseAddress));
        EventDataDescCreate(&EventData[8], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[9], targetImagePath_str.c_str(), (wcslen(targetImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[10], CallStack, (wcslen(CallStack) + 1) * sizeof(WCHAR));



        status = WriteETWEvents(EventData, TIRemoteAllocateVirtualMemory, 11);
        goto Exit;
    }
    case 24:
    {
        FILETIME st;
        GetSystemTimeAsFileTime(&st);
       
        PTRACE_EVENT_INFO pInfo = NULL;
        DWORD bufferSize = 0;

        UINT32 CallingThreadId, CallingProcessId, TargetProcessId, OriginalProcessId, TargetThreadId;
        UINT64 CallingProcessStartKey, TargetProcessStartKey, ApcRoutine, ApcArgument1;
        DWORD status = ERROR_SUCCESS;

        //
       // Testing out TDH APIs
       //
        status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        if (ERROR_INSUFFICIENT_BUFFER == status) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (pInfo == NULL) {
                // Handle allocation failure
                OutputDebugString(L"[!] Error allocating memory for event info\n");
                goto Exit;
            }

            // Get the event info
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }

        if (ERROR_SUCCESS != status) {
            // Handle error (could not obtain event info)
            free(pInfo);
            OutputDebugString(L"[!] Error getting event info\n");
            goto Exit;
        }
        for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            PROPERTY_DATA_DESCRIPTOR dataDescriptor;
            DWORD propertySize = 0;
            WCHAR* propertyName = (WCHAR*)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);

            dataDescriptor.PropertyName = (ULONGLONG)propertyName;
            dataDescriptor.ArrayIndex = ULONG_MAX;

            // Determine the size of the property
            status = TdhGetPropertySize(EventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
            if (status != ERROR_SUCCESS) {
                // Handle error
                wprintf(L"Error getting size for property %ls\n", propertyName);
                continue;
            }

            BYTE* propertyData = (BYTE*)malloc(propertySize);
            if (!propertyData) {
                // Handle allocation failure
                wprintf(L"Error allocating memory for property %ls\n", propertyName);
                continue;
            }

            // Get the property data
            status = TdhGetProperty(EventRecord, 0, NULL, 1, &dataDescriptor, propertySize, propertyData);
            if (status != ERROR_SUCCESS) {
                // Handle error
                wprintf(L"Error getting data for property %ls\n", propertyName);
                free(propertyData);
                continue;
            }
            switch (i) {
            case 0:
            {
                CallingProcessId = *(UINT32*)propertyData;
                break;
            }
            case 2:
            {
                CallingProcessStartKey = *(UINT64*)propertyData;
                break;
            }
            case 6:
            {
                CallingThreadId = *(UINT32*)propertyData;
                break;
            }
            case 8:
            {
                TargetProcessId = *(UINT32*)propertyData;
                break;
            }
            case 10:
            {
                TargetProcessStartKey = *(UINT64*)propertyData;
                break;
            }
            case 14:
            {
                TargetThreadId = *(UINT32*)propertyData;
            }
            case 16:
            {
                OriginalProcessId = *(UINT32*)propertyData;
                break;
            }
            case 21:
            {
                ApcRoutine = *(UINT64*)propertyData;
                break;
            }
            case 22:
            {
                ApcArgument1 = *(UINT64*)propertyData;
                break;
            }
            default:
            {
                break;
            }
            }
            free(propertyData);

        }

        if (GetImagePath(CallingProcessId, &sourceImagePath) != ERROR_SUCCESS) {
            ImagePath_str = L"Unknown";
        }
        else {
            ImagePath_str = sourceImagePath;
        }
        if (GetImagePath(TargetProcessId, &targetImagePath) != ERROR_SUCCESS) {
            targetImagePath_str = L"Unknown";
        }
        else {
            targetImagePath_str = targetImagePath;
        }

        CallStack = GetCallStack(EventRecord, extendedData, hProcess);

        EVENT_DATA_DESCRIPTOR EventData[13];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], &CallingThreadId, 4);
        EventDataDescCreate(&EventData[2], &CallingProcessId, 4);
        EventDataDescCreate(&EventData[3], &TargetProcessId, 4);
        EventDataDescCreate(&EventData[4], &TargetThreadId, 4);
        EventDataDescCreate(&EventData[5], &CallingProcessStartKey, 8);
        EventDataDescCreate(&EventData[6], &TargetProcessStartKey, 8);
        EventDataDescCreate(&EventData[7], &OriginalProcessId, 4);
        EventDataDescCreate(&EventData[8], &ApcRoutine, sizeof(ApcRoutine));
        EventDataDescCreate(&EventData[9], &ApcArgument1, sizeof(ApcArgument1));
        EventDataDescCreate(&EventData[10], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[11], targetImagePath_str.c_str(), (wcslen(targetImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[12], CallStack, (wcslen(CallStack) + 1) * sizeof(WCHAR));


        status = WriteETWEvents(EventData, TIQueueUserAPCEvent, 13);
        goto Exit;
    }
    case 26:
    {
        auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
        auto CallingProcessId{ GetData<UINT32>(data) };
        auto CallingProcessCreationTime{ GetData<FILETIME>(data) };
        auto CallingProcessStartKey{ GetData<UINT64>(data) };
        auto CallingProcessSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessSectionSignatureLevel{ GetData<UINT8>(data) };
        auto CallingProcessProtection{ GetData<UINT8>(data) };
        auto CallingThreadId{ GetData<UINT32>(data) };
        auto CallingThreadCreationTime{ GetData<FILETIME>(data) };
        auto TargetProcessId{ GetData<UINT32>(data) };
        auto TargetProcessCreateTime{ GetData<FILETIME>(data) };
        auto TargetProcessStartKey{ GetData<UINT64>(data) };
        auto TargetProcessSignatureLevel{ GetData<UINT8>(data) };
        auto TargetProcessSectionSignatureLevel{ GetData<UINT8>(data) };
        auto TargetProcessProtection{ GetData<UINT8>(data) };
        auto OriginalProcessId{ GetData<UINT32>(data) };
        auto OriginalProcessCreateTime{ GetData<FILETIME>(data) };
        auto OriginalProcessStartKey{ GetData<UINT64>(data) };
        auto OriginalProcessSignatureLevel{ GetData<UINT8>(data) };
        auto OriginalProcessProtection{ GetData<UINT8>(data) };
        auto BaseAddress{ GetData<UINT64>(data) };

        if (*CallingProcessId == *TargetProcessId) {
            goto Exit;
        }

        if (GetImagePath(*CallingProcessId, &sourceImagePath) != ERROR_SUCCESS) {
            ImagePath_str = L"Unknown";
        }
        else {
            ImagePath_str = sourceImagePath;
        }
        if (GetImagePath(*TargetProcessId, &targetImagePath) != ERROR_SUCCESS) {
            targetImagePath_str = L"Unknown";
        }
        else {
            targetImagePath_str = targetImagePath;
        }

        CallStack = GetCallStack(EventRecord, extendedData, hProcess);
        FILETIME st;
        GetSystemTimeAsFileTime(&st);
        EVENT_DATA_DESCRIPTOR EventData[11];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], CallingThreadId, 4);
        EventDataDescCreate(&EventData[2], CallingProcessId, 4);
        EventDataDescCreate(&EventData[3], TargetProcessId, 4);
        EventDataDescCreate(&EventData[4], CallingProcessStartKey, 8);
        EventDataDescCreate(&EventData[5], TargetProcessStartKey, 8);
        EventDataDescCreate(&EventData[6], OriginalProcessId, 4);
        EventDataDescCreate(&EventData[7], BaseAddress, sizeof(BaseAddress));
        EventDataDescCreate(&EventData[8], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[9], targetImagePath_str.c_str(), (wcslen(targetImagePath_str.c_str()) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[10], CallStack, (wcslen(CallStack) + 1) * sizeof(WCHAR));



        status = WriteETWEvents(EventData, TIRemoteAllocateVirtualMemory, 11);
        goto Exit;
    }
    default:
    {
        goto Exit;
    }
    }
Exit:
    if (sourceImagePath != nullptr) {
        delete[] sourceImagePath;
    }
    if (targetImagePath != nullptr) {
        delete[] targetImagePath;
    }
    if (CallStack != nullptr) {
        delete[] CallStack;
    }
    return 0;
}

BOOL WriteNetworkEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ wchar_t* Initiated
) {
    WCHAR wide_deststring_ip[INET_ADDRSTRLEN];
    WCHAR wide_sourcestring_ip[INET_ADDRSTRLEN];
    struct in_addr srceaddr = {};
    struct in_addr destaddr = {};
    UINT16 sourcePort, destPort;
    wchar_t* username = nullptr;
    wchar_t* pImagePath = nullptr;
    std::wstring ImagePath_str;
    std::wstring username_str;
    std::wstring sourcePort_str;
    std::wstring destPort_str;
    BOOL status = FALSE;
    REGHANDLE RegistrationHandle = NULL;

    auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
    auto PID{ GetData<UINT32>(data) };
    auto size{ GetData<UINT32>(data) };
    auto daddr{ GetData<UINT32>(data) };
    auto saddr{ GetData<UINT32>(data) };
    auto dport{ GetData<UINT16>(data) };
    auto sport{ GetData<UINT16>(data) };

    if (*PID == 4) {
        goto Exit;
    }

    if (Initiated == L"True") {

        destaddr.s_addr = *daddr;
        srceaddr.s_addr = *saddr;
        sourcePort == *sport;
        destPort == *dport;
        sourcePort_str = std::to_wstring(*sport);
        destPort_str = std::to_wstring(*dport);
    }
    if (Initiated == L"False") {
        destaddr.s_addr = *saddr;
        srceaddr.s_addr = *daddr;
        sourcePort = *dport;
        destPort = *sport;
        sourcePort_str = std::to_wstring(*dport);
        destPort_str = std::to_wstring(*sport);
    }

    //
    // convert port to widestring
    //


    //
    // add null terminator to wide string
    //
    sourcePort_str += L'\0';
    destPort_str += L'\0';

    if (&destaddr == NULL) {
        wide_deststring_ip[0] = '\0';
    }
    else {
        InetNtop(AF_INET, &destaddr, wide_deststring_ip, INET_ADDRSTRLEN);
    }

    if (&srceaddr == NULL) {
        wide_sourcestring_ip[0] = '\0';
    }
    else {
        InetNtop(AF_INET, &srceaddr, wide_sourcestring_ip, INET_ADDRSTRLEN);
    }
    //
    // removing ip addr 127.0.0.1 
    //
    if (wcscmp(wide_deststring_ip, L"127.0.0.1") == 0) {
        goto Exit;
    }

    //
    //Getting UserName
    //
    if (GetTokenUser(*PID, &username) != 0) {
        username_str = L"Unknown";
    }
    else {
        username_str = username;
    }

    //
    //Getting ImagePath
    //
    if (GetImagePath(*PID, &pImagePath) != ERROR_SUCCESS) {
        ImagePath_str = L"Unknown";
    }
    else {
        ImagePath_str = pImagePath;
    }

    FILETIME st;
    GetSystemTimeAsFileTime(&st);

    EVENT_DATA_DESCRIPTOR EventData[9];
    EventDataDescCreate(&EventData[0], &st, sizeof(st));
    EventDataDescCreate(&EventData[1], PID, 4);
    EventDataDescCreate(&EventData[2], &wide_sourcestring_ip, (wcslen(wide_sourcestring_ip) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[3], &wide_deststring_ip, (wcslen(wide_deststring_ip) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[4], &sourcePort, sizeof(UINT16));
    EventDataDescCreate(&EventData[5], &destPort, sizeof(UINT16));
    EventDataDescCreate(&EventData[6], Initiated, (wcslen(Initiated) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[7], username_str.c_str(), (wcslen(username_str.c_str()) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[8], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));

    status = WriteETWEvents(EventData, NetworkConnectionAccepted, 9);


Exit:
    if (pImagePath != nullptr) {
        delete[] pImagePath;
    }
    if (username != nullptr) {
        delete[] username;
    }
    return status;
}

BOOL WriteAMSIEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
    auto Session{ GetData<ULONG64>(data) };
    auto ScanStatus = GetData<UINT8>(data);
    auto ScanResult = GetData<UINT32>(data);
    auto AppName{ GetWideString(data) };
    auto ContentName = GetData<wchar_t*>(data);
    auto ContentSize = GetData<UINT32>(data);
    auto OriginalSize = GetData<UINT32>(data);
    auto Content = GetData<BYTE>(data);

    FILETIME st;
    GetSystemTimeAsFileTime(&st);

    //Writing Event to ETW
    EVENT_DATA_DESCRIPTOR EventData[5];
    EventDataDescCreate(&EventData[0], &st, sizeof(st));
    EventDataDescCreate(&EventData[1], &EventHeader->ProcessId, 4);
    EventDataDescCreate(&EventData[2], AppName, (wcslen(AppName) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[3], ScanResult, 4);
    EventDataDescCreate(&EventData[4], ContentSize, 4);

    NTSTATUS status = WriteETWEvents(EventData, AMSIEvents, 5);

    return TRUE;
}

BOOL WriteDotNetEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
    auto AssemblyID{ GetData<UINT64>(data) };
    auto AppDomainID{ GetData<UINT64>(data) };
    auto BindingID{ GetData<UINT64>(data) };
    auto AssemblyFlags{ GetData<UINT32>(data) };
    auto FullyQualifiedAssemblyName{ GetWideString(data) };
    auto ClrInstanceID{ GetData<UINT16>(data) };

    wchar_t* username = nullptr;
    wchar_t* pImagePath = nullptr;
    std::wstring ImagePath_str;
    std::wstring username_str;
    REGHANDLE RegistrationHandle = NULL;

    if (EventHeader->ProcessId == 4)
    {
        return FALSE;
    }

    std::wistringstream wiss(FullyQualifiedAssemblyName);
    std::vector<std::wstring> tokens;
    std::wstring token;
    while (std::getline(wiss, token, L',')) {
        tokens.push_back(token);
    }

    //Getting UserName
    if (GetTokenUser(EventHeader->ProcessId, &username) != 0) {
        username_str = L"Unknown - process potentially died";
    }
    else {
        username_str = username;
    }

    //Getting ImagePath
    if (GetImagePath(EventHeader->ProcessId, &pImagePath) != ERROR_SUCCESS) {
        ImagePath_str = L"Unknown - process potentially died";
    }
    else {
        ImagePath_str = pImagePath;
    }

    FILETIME st;
    GetSystemTimeAsFileTime(&st);


    //Writing Event to ETW
    EVENT_DATA_DESCRIPTOR EventData[6];
    EventDataDescCreate(&EventData[0], &st, sizeof(st));
    EventDataDescCreate(&EventData[1], &EventHeader->ProcessId, sizeof(ULONG));
    EventDataDescCreate(&EventData[2], tokens[0].c_str(), (wcslen(tokens[0].c_str()) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[3], username_str.c_str(), (wcslen(username_str.c_str()) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[4], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[5], ClrInstanceID, sizeof(ClrInstanceID));

    NTSTATUS status = WriteETWEvents(EventData, DotNetLoad, 6);
    
Exit:
    if (pImagePath != nullptr) {
        delete[] pImagePath;
    }
    if (username != nullptr) {
        delete[] username;
    }
    return TRUE;
}

BOOL WriteTaskSchedEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    switch (EventHeader->EventDescriptor.Id) {
    case 106: {
        auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
        auto TaskName{ GetWideString(data) };
        auto UserContext{ GetWideString(data) };

        FILETIME st;
        GetSystemTimeAsFileTime(&st);

        EVENT_DATA_DESCRIPTOR EventData[4];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], TaskName, (wcslen(TaskName) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[2], UserContext, (wcslen(UserContext) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[3], &EventHeader->ProcessId, 4);

        NTSTATUS status = WriteETWEvents(EventData, SchedTaskCreation, 4);

        break;
    }
    case 129: {
        auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
        auto TaskName{ GetWideString(data) };
        auto Path{ GetWideString(data) };
        auto ProcessId = GetData<UINT32>(data);
        FILETIME st;
        GetSystemTimeAsFileTime(&st);
        EVENT_DATA_DESCRIPTOR EventData[4];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], TaskName, (wcslen(TaskName) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[2], Path, (wcslen(Path) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[3], ProcessId, 4);

        NTSTATUS status = WriteETWEvents(EventData, SchedTaskStarted, 4);
        break;
    }
    default: {
        break;
    }
    }
    return TRUE;
}

BOOL WriteWMIEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    switch (EventHeader->EventDescriptor.Id) {
    case 5861:
    {
        auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
        auto Namespace{ GetWideString(data) };
        auto ESS{ GetWideString(data) };
        auto Consumer{ GetWideString(data) };
        auto PossibleCause{ GetWideString(data) };

        FILETIME st;
        GetSystemTimeAsFileTime(&st);

        EVENT_DATA_DESCRIPTOR EventData[5];
        EventDataDescCreate(&EventData[0], &st, sizeof(st));
        EventDataDescCreate(&EventData[1], Namespace, (wcslen(Namespace) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[2], ESS, (wcslen(ESS) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[3], Consumer, (wcslen(Consumer) + 1) * sizeof(WCHAR));
        EventDataDescCreate(&EventData[4], PossibleCause, (wcslen(PossibleCause) + 1) * sizeof(WCHAR));

        NTSTATUS status = WriteETWEvents(EventData, WMIFilterToConsumerBinding, 5);
        break;
    }
    }

    return TRUE;
}

wchar_t* GetCallStack(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER_EXTENDED_DATA_ITEM extendedData,
    _In_ HANDLE hProcess
) {
    std::string sSymSearchPathBuf;
    const char* szSymSearchPath = nullptr;
    szSymSearchPath = "srv*http://msdl.microsoft.com/download/symbols";
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_CASE_INSENSITIVE | SYMOPT_ALLOW_ZERO_ADDRESS | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS);
    BOOL ret = SymInitialize(hProcess, szSymSearchPath, TRUE);
    if (!ret) {
        printf("[!] SymInitialize failed: %d\n", GetLastError());
    }
    if (EventRecord->ExtendedDataCount != 0) {
        const int MAX_SYM_NAME_LEN = 1024;
        std::wstring wtext;
        for (USHORT i = 0; i < EventRecord->ExtendedDataCount; i++) {
            if (extendedData[i].ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
                auto stacktrace = reinterpret_cast<PEVENT_EXTENDED_ITEM_STACK_TRACE64>(extendedData[i].DataPtr);
                int stack_length = extendedData[i].DataSize / sizeof(ULONG64);
                for (int j = 0; j < stack_length; j++) {
                    DWORD64 dwDisplacement;
                    DWORD temp;
                    DWORD64 dwAddress = stacktrace->Address[j];
                    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME_LEN * sizeof(TCHAR)];
                    PSYMBOL_INFOW pSymbol = (PSYMBOL_INFOW)buffer;
                    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
                    pSymbol->MaxNameLen = MAX_SYM_NAME_LEN;
                    if (SymFromAddrW(hProcess, dwAddress, &dwDisplacement, pSymbol)) {
                        wtext += pSymbol->Name;
                    }
                    else {
                        wtext += L"";
                    }
                    wtext += L" ";
                }
            }
        }

        wtext.erase(wtext.size() - 2);
        size_t wtext_len = wtext.length() + 1;
        wchar_t* result = new wchar_t[wtext_len];
        wcscpy_s(result, wtext_len, wtext.c_str());
        return result;
    }
    SymCleanup(hProcess);
}

BOOL WriteRPCEvent(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ EVENT_DESCRIPTOR RPCEvent,
    _In_ wchar_t* InterfaceString,
    _In_ wchar_t* MethodString,
    _In_ wchar_t* szInterfaceUUID,
    _In_ wchar_t* CallStack
) {
    //Getting Data
    wchar_t* username = nullptr;
    std::wstring username_str;
    wchar_t* pImagePath = nullptr;
    std::wstring ImagePath_str;
    PEVENT_HEADER_EXTENDED_DATA_ITEM extendedData = EventRecord->ExtendedData;
    HANDLE hProcess = GetCurrentProcess();

    auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
    auto interfaceUUID{ GetData<GUID>(data) };
    auto procNum{ GetData<UINT32>(data) };
    auto protocol{ GetData<UINT32>(data) };
    auto networkAddress{ GetWideString(data) };
    auto endpoint{ GetWideString(data) };
    auto options{ GetWideString(data) };
    auto authenticationLevel{ GetData<UINT32>(data) };
    auto authenticationService{ GetData<UINT32>(data) };
    auto impersonationLevel{ GetData<UINT32>(data) };

    //Getting UserName
    if (GetTokenUser(EventHeader->ProcessId, &username) != 0) {
        username_str = L"Unknown";
    }
    else {
        username_str = username;
    }

    //Getting ImagePath
    if (GetImagePath((DWORD)EventHeader->ProcessId, &pImagePath) != 0) {
        ImagePath_str = L"Unknown - process potentially died";
    }
    else {
        ImagePath_str = pImagePath;
    }

    FILETIME st;
    GetSystemTimeAsFileTime(&st);

    //Writing Event to ETW
    EVENT_DATA_DESCRIPTOR EventData[12];
    EventDataDescCreate(&EventData[0], &st, sizeof(st));
    EventDataDescCreate(&EventData[1], szInterfaceUUID, (wcslen(szInterfaceUUID) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[2], procNum, 4);
    EventDataDescCreate(&EventData[3], protocol, 4);
    EventDataDescCreate(&EventData[4], &EventHeader->ProcessId, 4);
    EventDataDescCreate(&EventData[5], networkAddress, (wcslen(networkAddress) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[6], endpoint, (wcslen(endpoint) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[7], InterfaceString, (wcslen(InterfaceString) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[8], MethodString, (wcslen(MethodString) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[9], username_str.c_str(), (wcslen(username_str.c_str()) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[10], ImagePath_str.c_str(), (wcslen(ImagePath_str.c_str()) + 1) * sizeof(WCHAR));
    EventDataDescCreate(&EventData[11], CallStack, (wcslen(CallStack) + 1) * sizeof(WCHAR));

    NTSTATUS status = WriteETWEvents(EventData, RPCEvent, 12);
    
    return TRUE;
}

BOOL RpcEvent(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ EVENT_DESCRIPTOR RPCEvent
) {
    PEVENT_HEADER_EXTENDED_DATA_ITEM extendedData = EventRecord->ExtendedData;
    HANDLE hProcess = GetCurrentProcess();
    auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
    auto interfaceUUID{ GetData<GUID>(data) };
    auto procNum{ GetData<UINT32>(data) };
    wchar_t szInterfaceUUID[64] = { 0 };
    StringFromGUID2(*interfaceUUID, szInterfaceUUID, 64);


    //MS-SCMR {367ABB81-9844-35F1-AD32-98F038001003}
    if (wcscmp(szInterfaceUUID, L"{367ABB81-9844-35F1-AD32-98F038001003}") == 0) {
        const wchar_t* InterfaceString = L"MS-SCMR";
        switch (*procNum)
        {
        case 12:
        {
            const wchar_t* MethodString = L"RCreateServiceW";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        default:
        {
            break;
        }
        }
        return TRUE;
    }
    //MS-DRSR {E3514235-4B06-11D1-AB04-00C04FC2DCD2}
    if (wcscmp(szInterfaceUUID, L"{E3514235-4B06-11D1-AB04-00C04FC2DCD2}") == 0) {
        const wchar_t* InterfaceString = L"MS-DRSR";
        switch (*procNum) {
        case 3:
        {
            const wchar_t* MethodString = L"GetNCChanges";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        default: {
            break;
        }
        }
        return TRUE;
    }
    //MS-RRP {338CD001-2244-31F1-AAAA-900038001003}
    if (wcscmp(szInterfaceUUID, L"{338CD001-2244-31F1-AAAA-900038001003}") == 0) {
        const wchar_t* InterfaceString = L"MS-RRP";
        switch (*procNum) {
        case 6:
        {
            const wchar_t* MethodString = L"BaseRegCreateKey";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        case 22:
        {
            const wchar_t* MethodString = L"BaseRegSetValue";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        default:
        {
            break;
        }

        }
        return TRUE;
    }
    //MS-SRVS {4B324FC8-1670-01D3-1278-5A47BF6EE188}
    if (wcscmp(szInterfaceUUID, L"{4B324FC8-1670-01D3-1278-5A47BF6EE188}") == 0) {
        const wchar_t* InterfaceString = L"MS-SRVS";
        switch (*procNum) {
        case 12:
        {
            const wchar_t* MethodString = L"NetrSessionEnum";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        default:
        {
            break;
        }
        }
        return TRUE;
    }
    //MS-RPRN {12345678-1234-ABCD-EF00-0123456789AB}
    if (wcscmp(szInterfaceUUID, L"{12345678-1234-ABCD-EF00-0123456789AB}") == 0) {
        const wchar_t* InterfaceString = L"MS-RPRN";
        switch (*procNum) {
        case 89:
        {
            const wchar_t* MethodString = L"RpcAddPrinterDriverEx";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        default:
        {
            break;
        }
        }
        return TRUE;
    }

    //MS-PAR 76F03F96-CDFD-44FC-A22C-64950A001209
    if (wcscmp(szInterfaceUUID, L"{76F03F96-CDFD-44FC-A22C-64950A001209}") == 0) {
        const wchar_t* InterfaceString = L"MS-PAR";
        switch (*procNum) {
        case 39:
        {
            const wchar_t* MethodString = L"RpcAsyncAddPrinterDriver";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        default:
        {
            break;
        }
        }
        return TRUE;
    }
    // MS-EFSR {D9A0A0C0-150F-11D1-8C7A-00C04FC297EB} || {C681D488-D850-11D0-8C52-00C04FD90F7E}"
    if ((wcscmp(szInterfaceUUID, L"{C681D488-D850-11D0-8C52-00C04FD90F7E}") == 0) || (wcscmp(szInterfaceUUID, L"{DF1941C5-FE89-4E79-BF10-463657ACF44D}") == 0)) {
        const wchar_t* InterfaceString = L"MS-EFSR";
        switch (*procNum) {
        case 0:
        {
            const wchar_t* MethodString = L"EfsRpcOpenFileRaw";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        case 4:
        {
            const wchar_t* MethodString = L"EfsRpcEncryptFileSrv";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        case 5:
        {
            const wchar_t* MethodString = L"EfsRpcDecryptFileSrv";
            wchar_t* CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            BOOL WriteEvent = WriteRPCEvent(EventRecord, EventHeader, RPCEvent, (wchar_t*)InterfaceString, (wchar_t*)MethodString, szInterfaceUUID, CallStack);
            delete[] CallStack;
            break;
        }
        default:
        {
            break;
        }
        }
        return TRUE;
    }

}

BOOL DPAPIEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    switch (EventHeader->EventDescriptor.Id) {
    case 16385:
    {
        auto data{ reinterpret_cast<byte*>(EventRecord->UserData) };
        auto OperationType{ GetWideString(data) };
        auto DataDescription{ GetWideString(data) };
        auto MasterKeyGUID = GetData<GUID>(data);
        auto Flags = GetData<UINT32>(data);
        auto ProtectionFlags = GetData<UINT32>(data);
        auto ReturnValue = GetData<UINT32>(data);
        auto CallerProcessStartKey = GetData<UINT64>(data);
        auto CallerProcessID = GetData<UINT32>(data);
        auto CallerProcessCreationTime = GetData<UINT64>(data);
        auto PlainTextDataSize = GetData<UINT32>(data);

        FILETIME st;
        GetSystemTimeAsFileTime(&st);

        //
        //Seeing if OperationType == SPCryptUnprotect
        //
        if (wcscmp(OperationType, L"SPCryptUnprotect") == 0) {

            EVENT_DATA_DESCRIPTOR EventData[6];
            EventDataDescCreate(&EventData[0], &st, sizeof(st));
            EventDataDescCreate(&EventData[1], OperationType, (wcslen(OperationType) + 1) * sizeof(WCHAR));
            EventDataDescCreate(&EventData[2], DataDescription, (wcslen(DataDescription) + 1) * sizeof(WCHAR));
            EventDataDescCreate(&EventData[3], CallerProcessID, 4);
            EventDataDescCreate(&EventData[4], Flags, 4);
            EventDataDescCreate(&EventData[5], ProtectionFlags, 4);

            NTSTATUS status = WriteETWEvents(EventData, DPAPIEvent, 6);
            break;
        }
        break;
    }
    default:
    {
        break;
    }
    }

Exit:
    return TRUE;
}