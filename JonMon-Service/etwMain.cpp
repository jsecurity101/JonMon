#include <ws2tcpip.h>
#include <Windows.h>
#include <sstream>
#include <vector>
#include <stdio.h>
#include <DbgHelp.h>
#include <thread>
#include <mutex>
#include <algorithm>
#include <regex>
#include "global.h"
#include "context.h"
#include "etwMain.h"
#include "service.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "dbghelp.lib")

DWORD lsassPID = 0;
SYSTEMTIME lastEventTime;

DWORD StopETWTrace() {
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

DWORD CheckLSASSPID() {
    //
    // Enumerate initialProcessList to find the LSASS PID
    //
    Sleep(2000);
    for (auto& process : initialProcessList) {
        //
        // print out each process id and process name
        //
        std::wstring lsassSubstring = L"lsass.exe";
        if (process.processName.find(lsassSubstring) != std::wstring::npos) {
            return process.processId;
        }
    }
}

DWORD TraceEvent(
    _In_ LPCWSTR Name,
    _In_ GUID TraceGuid,
    _In_ EventSchema_Full* EventSchemaStruct
) {
    std::thread initialProcesses(InitialProcesses);
    std::thread updateThread(UpdateProcessListPeriodically);
    std::thread clearThread(ClearListPeriodically);

    //
    // Detach threads
    //
    initialProcesses.detach();
    updateThread.detach();
    clearThread.detach();

    printf("[+] Starting ETW Trace\n");
    TRACEHANDLE hTrace = 0;
    ULONG result, bufferSize;
    EVENT_TRACE_LOGFILEW trace;
    EVENT_TRACE_PROPERTIES* traceProp = nullptr;

    lsassPID = CheckLSASSPID();

    memset(&trace, 0, sizeof(EVENT_TRACE_LOGFILEW));
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.LoggerName = (LPWSTR)Name;
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)ProcessEvent;

    //
    // Calculate buffer size
    //
    ULONG nameLength = (ULONG)(wcslen(Name) + 1);
    bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + nameLength * sizeof(WCHAR);

    //
    // Allocate memory for EVENT_TRACE_PROPERTIES and logger name
    //
    traceProp = (EVENT_TRACE_PROPERTIES*)LocalAlloc(LPTR, bufferSize);
    if (traceProp == nullptr) {
        printf("Failed to allocate memory for trace properties\n");
        return ERROR_OUTOFMEMORY;
    }

    //
    // Initialize EVENT_TRACE_PROPERTIES
    //
    traceProp->Wnode.BufferSize = bufferSize;
    traceProp->Wnode.ClientContext = 2;
    traceProp->Wnode.Guid = TraceGuid;
    traceProp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    traceProp->LogFileNameOffset = 0;
    traceProp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    //
    // Set logger name
    //
    LPWSTR loggerNamePtr = (LPWSTR)((BYTE*)traceProp + traceProp->LoggerNameOffset);
    wcscpy(loggerNamePtr, Name);

    //
    // Start the trace
    //
    if ((result = StartTraceW(&hTrace, Name, traceProp)) != ERROR_SUCCESS) {
        OutputDebugStringW(L"Error starting trace\n");
        LocalFree(traceProp);
        return result;
    }

    //
    // Set up and enable trace parameters
    //
    ENABLE_TRACE_PARAMETERS enableTraceParameters;
    ZeroMemory(&enableTraceParameters, sizeof(ENABLE_TRACE_PARAMETERS));
    enableTraceParameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    enableTraceParameters.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;

    printf("[+] JonMon Trace started\n");

    if ((result = EnableTraceEx2(
        hTrace,
        &JonMonTraceLogging,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0,
        0,
        0,
        0
    )) != ERROR_SUCCESS) {
        OutputDebugStringW(L"Error enabling trace\n");
        printf("Error: %lu\n", result);
        LocalFree(traceProp);  // Ensure traceProp is freed
        CloseTrace(hTrace);    // Ensure hTrace is closed
        return result;
    }

    //
    //DotNet Events
    //
    if (EventSchemaStruct->DotNetLoad_Events)
    {
        if ((result = EnableTraceEx2(
            hTrace,
            &DotNet_Provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            0x8,
            0,
            0,
            NULL
        )) != ERROR_SUCCESS) {
            OutputDebugString(L"[!] Error EnableTraceEx - DotNet\n");
        }
    }

    //
    // WMI Events
    //
    if (EventSchemaStruct->WMIEventSubscription_Events)
    {
        if ((result = EnableTraceEx2(
            hTrace,
            &WMIActivty_Provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            0,
            0,
            0,
            &enableTraceParameters
        )) != ERROR_SUCCESS) {
            OutputDebugString(L"[!] Error EnableTraceEx - WMI\n");
        }
    }

    //
    // RPC Events
    //
    if (EventSchemaStruct->RPC_Events)
    {
        if ((result = EnableTraceEx2(
            hTrace,
            &RPC_Provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            0,
            0,
            0,
            &enableTraceParameters
        )) != ERROR_SUCCESS) {
            OutputDebugString(L"[!] Error EnableTraceEx - RPC\n");
        }
    }

    //
    // AMSI
    //
    if (EventSchemaStruct->AMSI_Events)
    {
        if ((result = EnableTraceEx2(
            hTrace,
            &AMSI_Provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            0,
            0,
            0,
            &enableTraceParameters
        )) != ERROR_SUCCESS) {
            OutputDebugString(L"[!] Error EnableTraceEx - RPC\n");
        }
    }

    //
    // Network Events
    //
    if (EventSchemaStruct->Network_Events)
    {
        if ((result = EnableTraceEx2(
            hTrace,
            &Network_Provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            0,
            0x10,
            0,
            &enableTraceParameters
        )) != ERROR_SUCCESS) {
            OutputDebugString(L"[!] Error EnableTraceEx - RPC\n");
        }
    }

    //
    // Threat Intellgiene Events
    //
    if (EventSchemaStruct->ThreatIntelligence_Events)
    {
		OutputDebugStringW(L"Threat Intelligence Events Enabled\n");
        ULONGLONG matchAnyKeyword = 0x0;
		if (EventSchemaStruct->ThreatIntelligence_Events_RemoteReadProcessMemory)
		{
			OutputDebugStringW(L"RemoteReadProcessMemory Enabled\n");
			matchAnyKeyword |= 0x20000;
		}
        if (EventSchemaStruct->ThreatIntelligence_Events_RemoteWriteProcessMemory)
        {
			OutputDebugStringW(L"RemoteWriteProcessMemory Enabled\n");
			matchAnyKeyword |= 0x80000;
        }
        if (EventSchemaStruct->ThreatIntelligence_Events_RemoteVirtualAllocation)
        {
			OutputDebugStringW(L"RemoteVirtualAllocation Enabled\n");
			matchAnyKeyword |= (0x4 | 0x8);
        }
		if (EventSchemaStruct->ThreatIntelligence_Events_RemoteQueueUserAPC)
		{
			OutputDebugStringW(L"RemoteQueueUserAPC Enabled\n");
			matchAnyKeyword |= (0x1000 | 0x2000);
		}

        if ((result = EnableTraceEx2(
            hTrace,
            &ThreatIntel_Provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            matchAnyKeyword,
            0,
            0,
            &enableTraceParameters
        )) != ERROR_SUCCESS) {
            OutputDebugString(L"[!] Error EnableTraceEx - ThreatIntelligence\n");
        }
    }

    //
    // Free traceProp after trace is successfully started
    //
    LocalFree(traceProp);

    hTrace = OpenTraceW(&trace);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        OutputDebugString(L"[!] Error OpenTrace\n");
        return 1;
    }


    //
    // Process the trace
    //
    result = ProcessTrace(&hTrace, 1, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        printf("[!] Error ProcessTrace\n");
        CloseTrace(hTrace);  // Ensure hTrace is closed
        return result;
    }

    //
    // Close trace handle after processing is complete
    //
    CloseTrace(hTrace);
    return 0;

}

void ProcessEvent(
    _In_ PEVENT_RECORD EventRecord
) {
    PEVENT_HEADER eventHeader = &EventRecord->EventHeader;
    PEVENT_DESCRIPTOR eventDescriptor = &eventHeader->EventDescriptor;
    NTSTATUS status;


    if (eventHeader->ProviderId == JonMonTraceLogging) {
        status = WriteJonMonTraceLoggingEvents(EventRecord, eventHeader);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error writing JonMon Trace Logging Events\n");
        }
    }
    if (eventHeader->ProviderId == DotNet_Provider) {
        switch (eventDescriptor->Id) {
        case 154: {
            status = WriteDotNetEvents(EventRecord, eventHeader);
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing DotNet Events\n");
            }
            break;
        }
        default: {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == Network_Provider)
    {
        status = WriteNetworkEvents(EventRecord, eventHeader);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error writing Network Events\n");
        }
    }
    if (eventHeader->ProviderId == DPAPI_Provider)
    {
        switch (eventDescriptor->Id) {
        case 16385: {
            status = WriteDpapiEvents(EventRecord, eventHeader);
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing DPAPI Events\n");
            }
            break;
        }
        default: {
            break;
        }
        }
    }
    if (eventHeader->ProviderId == WMIActivty_Provider) {
        switch (eventDescriptor->Id) {
        case 5861:
        {
            status = WriteWMIEvents(EventRecord, eventHeader);
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing WMI Events\n");
            }
            break;
        }
        default:
        {
            break;
        }
        }


    }
    if (eventHeader->ProviderId == RPC_Provider) {
        switch (eventDescriptor->Id) {
        case 5:
        {
            status = WriteRpcEvents(EventRecord, eventHeader, 0); // 0 == CLIENT
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing RPC Events\n");
            }

            break;
        }
        case 6:
        {
            status = WriteRpcEvents(EventRecord, eventHeader, 1); // 1 == SERVER
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing RPC Events\n");
            }
            break;
        }
        default: {
            break;
        }

        }
    }
    if (eventHeader->ProviderId == AMSI_Provider) {
        switch (eventDescriptor->Id) {
        case 1101:
        {
            status = WriteAMSIEvents(EventRecord, eventHeader);
            if (status != ERROR_SUCCESS) {
                OutputDebugString(L"Error writing AMSI Events\n");
            }
            break;
        }
        default:
        {
            break;
        }


        }
    }
    if (eventHeader->ProviderId == ThreatIntel_Provider) {
        status = WriteThreatIntelEvents(EventRecord, eventHeader);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error writing Threat Intelligence Events\n");
        }
    }
}


NTSTATUS WriteJonMonTraceLoggingEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;
    int vectorCapacity = 10;
    int vectorSize = 0;
    SYSTEMTIME systemTime;

    // Fetch initial event information size
    status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (!pInfo) {
            OutputDebugString(L"Error allocating memory for event info\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
        status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
    }
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error fetching event info\n");
        goto Exit;
    }

    // Allocate memory for property data vector
    propertyDataVector = (BYTE**)malloc(vectorCapacity * sizeof(BYTE*));
    if (!propertyDataVector) {
        OutputDebugString(L"Error allocating memory for propertyDataVector\n");
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto Exit;
    }

    // Process each property in the event
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
        DWORD propertySize = 0;
        WCHAR* propertyName = (WCHAR*)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        dataDescriptor.PropertyName = (ULONGLONG)propertyName;
        dataDescriptor.ArrayIndex = ULONG_MAX;

        // Determine the size of the property
        status = TdhGetPropertySize(EventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
        if (status != ERROR_SUCCESS) {
            wprintf(L"Error getting size for property %ls\n", propertyName);
            goto Exit;
        }

        BYTE* propertyData = (BYTE*)malloc(propertySize);
        if (!propertyData) {
            wprintf(L"Error allocating memory for property %ls\n", propertyName);
            goto Exit;
        }

        // Get the actual property data
        status = TdhGetProperty(EventRecord, 0, NULL, 1, &dataDescriptor, propertySize, propertyData);
        if (status != ERROR_SUCCESS) {
            wprintf(L"Error getting data for property %ls\n", propertyName);
            goto Exit;
        }

        // Check if we need to resize the vector
        if (vectorSize == vectorCapacity) {
            BYTE** resizedVector = (BYTE**)realloc(propertyDataVector, 2 * vectorCapacity * sizeof(BYTE*));
            if (!resizedVector) {
                OutputDebugString(L"Error resizing propertyDataVector\n");
                free(propertyData);
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
            propertyDataVector = resizedVector;
            vectorCapacity *= 2;
        }

        // Add the data to the vector
        propertyDataVector[vectorSize++] = propertyData;
    }

    switch (*(INT32*)propertyDataVector[0])
    {
    case 1:
    {
        BOOL ProcessReParented = FALSE;
        printf("Process Creation Event\n");

        PProcessCreationEvent processCreationEvent = (PProcessCreationEvent)malloc(sizeof(ProcessCreationEvent));
        if (processCreationEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for processCreationEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        processCreationEvent->EventId = *(INT32*)propertyDataVector[0];
        processCreationEvent->ProcessId = *(INT64*)propertyDataVector[1];
        processCreationEvent->ProcessStartKey = *(UINT64*)propertyDataVector[2];
        processCreationEvent->ParentProcessId = *(INT64*)propertyDataVector[3];
        processCreationEvent->ParentProcessStartKey = *(UINT64*)propertyDataVector[4];
        processCreationEvent->CreatorProcessId = *(INT64*)propertyDataVector[5];
        processCreationEvent->CreatorThreadId = *(INT64*)propertyDataVector[6];
        processCreationEvent->CommandLine = (WCHAR*)propertyDataVector[7];
        processCreationEvent->EventTime = *(FILETIME*)propertyDataVector[8];

        if (processCreationEvent->ParentProcessId != processCreationEvent->CreatorProcessId) {
            ProcessReParented = TRUE;
        }

        PProcessInformation processInformation = GetProcessName(processCreationEvent->ProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }

        PProcessInformation parentProcessInformation;
        parentProcessInformation = GetProcessName(processCreationEvent->ParentProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (parentProcessInformation == nullptr) {
            printf("Parent Process not found\n");
            break;

        }

        FileTimeToSystemTime(&processCreationEvent->EventTime, &systemTime);

        EventWriteProcessCreation(
            &systemTime,
            processCreationEvent->CreatorThreadId,
            processCreationEvent->CreatorProcessId,
            processCreationEvent->ParentProcessId,
            processCreationEvent->ParentProcessStartKey,
            parentProcessInformation->processName.c_str(),
            parentProcessInformation->userName.c_str(),
            parentProcessInformation->authenticationId.LowPart,
            parentProcessInformation->integrityLevel.c_str(),
            parentProcessInformation->sessionId,
            parentProcessInformation->tokenType,
            processInformation->processName.c_str(),
            processCreationEvent->CommandLine,
            processCreationEvent->ProcessId,
            processCreationEvent->ProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->linkedAuthenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            processInformation->tokenType,
            ProcessReParented
        );

        free(processCreationEvent);


        break;
    }
    case 2:
    {
        printf("Process Termination Event\n");
        PProcessTerminationEvent processTerminationEvent = (PProcessTerminationEvent)malloc(sizeof(ProcessTerminationEvent));
        if (processTerminationEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for processTerminationEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        processTerminationEvent->EventId = *(INT32*)propertyDataVector[0];
        processTerminationEvent->ProcessId = *(INT64*)propertyDataVector[1];
        processTerminationEvent->ProcessStartKey = *(UINT64*)propertyDataVector[2];
        processTerminationEvent->ParentProcessId = *(INT64*)propertyDataVector[3];
        processTerminationEvent->ParentProcessStartKey = *(UINT64*)propertyDataVector[4];
        processTerminationEvent->EventTime = *(FILETIME*)propertyDataVector[5];

        PProcessInformation processInformation = GetProcessName(processTerminationEvent->ProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }

        FileTimeToSystemTime(&processTerminationEvent->EventTime, &systemTime);

        EventWriteProcessTerminate(
            &systemTime,
            processTerminationEvent->ParentProcessId,
            processTerminationEvent->ParentProcessStartKey,
            processInformation->processName.c_str(),
            processTerminationEvent->ProcessId
        );

        free(processTerminationEvent);

        break;

    }
    case 3:
    {
        printf("Remote Thread Creation Event\n");
        PRemoteThreadCreationEvent remoteThreadCreationEvent = (PRemoteThreadCreationEvent)malloc(sizeof(RemoteThreadCreationEvent));
        if (remoteThreadCreationEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for remoteThreadCreationEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        remoteThreadCreationEvent->EventId = *(INT32*)propertyDataVector[0];
        remoteThreadCreationEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        remoteThreadCreationEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        remoteThreadCreationEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        remoteThreadCreationEvent->NewThreadId = *(INT64*)propertyDataVector[4];
        remoteThreadCreationEvent->TargetProcessId = *(INT64*)propertyDataVector[5];
        remoteThreadCreationEvent->TargetProcessStartKey = *(UINT64*)propertyDataVector[6];
        remoteThreadCreationEvent->EventTime = *(FILETIME*)propertyDataVector[7];

        PProcessInformation processInformation = GetProcessName(remoteThreadCreationEvent->TargetProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }

        PProcessInformation sourceProcessInformation;
        sourceProcessInformation = GetProcessName(remoteThreadCreationEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (sourceProcessInformation == nullptr) {
            printf("Source Process not found\n");
            break;

        }

        FileTimeToSystemTime(&remoteThreadCreationEvent->EventTime, &systemTime);

        EventWriteRemoteThreadCreation(
            &systemTime,
            remoteThreadCreationEvent->SourceProcessId,
            remoteThreadCreationEvent->SourceProcessStartKey,
            remoteThreadCreationEvent->SourceThreadId,
            sourceProcessInformation->processName.c_str(),
            sourceProcessInformation->userName.c_str(),
            sourceProcessInformation->authenticationId.LowPart,
            sourceProcessInformation->integrityLevel.c_str(),
            sourceProcessInformation->sessionId,
            sourceProcessInformation->tokenType,
            processInformation->processName.c_str(),
            remoteThreadCreationEvent->TargetProcessId,
            remoteThreadCreationEvent->TargetProcessStartKey,
            remoteThreadCreationEvent->NewThreadId,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->linkedAuthenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId
        );

        //
        // Free the memory allocated for the event data
        //
        free(remoteThreadCreationEvent);

        break;

    }
    case 4:
    {
        printf("Load Image Event\n");
        PLoadImageEvent loadImageEvent = (PLoadImageEvent)malloc(sizeof(LoadImageEvent));
        if (loadImageEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for loadImageEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        loadImageEvent->EventId = *(INT32*)propertyDataVector[0];
        loadImageEvent->ProcessId = *(INT64*)propertyDataVector[1];
        loadImageEvent->ProcessStartKey = *(UINT64*)propertyDataVector[2];
        loadImageEvent->ThreadId = *(INT64*)propertyDataVector[3];
        loadImageEvent->SystemModeImage = *(ULONG*)propertyDataVector[4];
        loadImageEvent->ImageName = (WCHAR*)propertyDataVector[5];
        loadImageEvent->EventTime = *(FILETIME*)propertyDataVector[6];

        FileTimeToSystemTime(&loadImageEvent->EventTime, &systemTime);


        if (loadImageEvent->SystemModeImage == 1) {
            printf("System Mode Image\n");
            EventWriteImageLoaded(
                &systemTime,
                NULL,
                loadImageEvent->ProcessId,
                loadImageEvent->ThreadId,
                loadImageEvent->ProcessStartKey,
                NULL,
                0,
                0,
                NULL,
                0,
                0,
                loadImageEvent->ImageName,
                loadImageEvent->SystemModeImage,
                );
            free(loadImageEvent);
            break;
        }

        PProcessInformation processInformation;
        processInformation = GetProcessName(loadImageEvent->ProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }


        EventWriteImageLoaded(
            &systemTime,
            processInformation->processName.c_str(),
            loadImageEvent->ProcessId,
            loadImageEvent->ThreadId,
            loadImageEvent->ProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->linkedAuthenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            processInformation->tokenType,
            loadImageEvent->ImageName,
            loadImageEvent->SystemModeImage,
            );

        //
        // Free the memory allocated for the event data
        //
        free(loadImageEvent);

        break;
    }
    case 5:
    {
        printf("Process Handle Event\n");
        PProcessHandleEvent processHandleEvent = (PProcessHandleEvent)malloc(sizeof(ProcessHandleEvent));
        if (processHandleEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for processHandleEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        processHandleEvent->EventId = *(INT32*)propertyDataVector[0];
        processHandleEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        processHandleEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        processHandleEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        processHandleEvent->TargetProcessId = *(INT64*)propertyDataVector[4];
        processHandleEvent->TargetProcessStartKey = *(UINT64*)propertyDataVector[5];
        processHandleEvent->OperationType = *(INT32*)propertyDataVector[6];
        processHandleEvent->DesiredAccess = *(INT32*)propertyDataVector[7];
        processHandleEvent->EventTime = *(FILETIME*)propertyDataVector[8];

        FileTimeToSystemTime(&processHandleEvent->EventTime, &systemTime);

        PProcessInformation sourceProcessInformation;
        sourceProcessInformation = GetProcessName(processHandleEvent->SourceProcessId);

        // Check if processInformation is not nullptr before dereferencing it
        if (sourceProcessInformation == nullptr) {
            printf("Source Process not found\n");
            break;

        }

        //
        // Check to see if source process contains JonMon-Service.exe
        //
        if (sourceProcessInformation->processName.find(L"Windows\\JonMon-Service.exe") != std::string::npos) {
            printf("Exiting because JonMon-Service is the source process\n");
            break;
        }


        PProcessInformation targetProcessInformation;
        targetProcessInformation = GetProcessName(processHandleEvent->TargetProcessId);

        // Check if processInformation is not nullptr before dereferencing it
        if (targetProcessInformation == nullptr) {
            printf("Target Process not found\n");
            break;
        }

        EventWriteProcessAccess(
            &systemTime,
            processHandleEvent->SourceProcessId,
            processHandleEvent->SourceThreadId,
            processHandleEvent->SourceProcessStartKey,
            sourceProcessInformation->processName.c_str(),
            sourceProcessInformation->userName.c_str(),
            sourceProcessInformation->authenticationId.LowPart,
            sourceProcessInformation->integrityLevel.c_str(),
            sourceProcessInformation->sessionId,
            sourceProcessInformation->tokenType,
            processHandleEvent->TargetProcessId,
            processHandleEvent->TargetProcessStartKey,
            targetProcessInformation->processName.c_str(),
            targetProcessInformation->userName.c_str(),
            targetProcessInformation->authenticationId.LowPart,
            targetProcessInformation->linkedAuthenticationId.LowPart,
            targetProcessInformation->integrityLevel.c_str(),
            targetProcessInformation->sessionId,
            targetProcessInformation->tokenType,
            processHandleEvent->DesiredAccess,
            processHandleEvent->OperationType
        );


        //
        // Free the memory allocated for the event data
        //
        free(processHandleEvent);
        break;
    }
    case 6:
    {
        printf("Registry Save Key Event\n");
        PRegistrySaveKeyEvent registrySaveKeyEvent = (PRegistrySaveKeyEvent)malloc(sizeof(RegistrySaveKeyEvent));
        if (registrySaveKeyEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for registrySaveKeyEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        registrySaveKeyEvent->EventId = *(INT32*)propertyDataVector[0];
        registrySaveKeyEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        registrySaveKeyEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        registrySaveKeyEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        registrySaveKeyEvent->KeyPath = (WCHAR*)propertyDataVector[4];
        registrySaveKeyEvent->EventTime = *(FILETIME*)propertyDataVector[5];

        FileTimeToSystemTime(&registrySaveKeyEvent->EventTime, &systemTime);

        PProcessInformation processInformation;
        processInformation = GetProcessName(registrySaveKeyEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }


        EventWriteRegistrySaveKey(
            &systemTime,
            processInformation->processName.c_str(),
            registrySaveKeyEvent->SourceProcessId,
            registrySaveKeyEvent->SourceThreadId,
            registrySaveKeyEvent->SourceProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            registrySaveKeyEvent->KeyPath
        );


        //
        // Free the memory allocated for the event data
        //
        free(registrySaveKeyEvent);
        break;
    }
    case 8:
    {
        printf("Registry Set Value Key Event\n");
        PRegistrySetValueKeyEvent registrySetValueKeyEvent = (PRegistrySetValueKeyEvent)malloc(sizeof(RegistrySetValueKeyEvent));
        if (registrySetValueKeyEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for registrySetValueKeyEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        registrySetValueKeyEvent->EventId = *(INT32*)propertyDataVector[0];
        registrySetValueKeyEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        registrySetValueKeyEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        registrySetValueKeyEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        registrySetValueKeyEvent->KeyPath = (WCHAR*)propertyDataVector[4];
        registrySetValueKeyEvent->ValueName = (WCHAR*)propertyDataVector[5];
        registrySetValueKeyEvent->Data = (WCHAR*)propertyDataVector[6];
        registrySetValueKeyEvent->Type = *(INT32*)propertyDataVector[7];
        registrySetValueKeyEvent->DataSize = *(INT32*)propertyDataVector[8];
        registrySetValueKeyEvent->EventTime = *(FILETIME*)propertyDataVector[9];

        FileTimeToSystemTime(&registrySetValueKeyEvent->EventTime, &systemTime);

        PProcessInformation processInformation;
        processInformation = GetProcessName(registrySetValueKeyEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }


        EventWriteRegistrySetValueKey(
            &systemTime,
            processInformation->processName.c_str(),
            registrySetValueKeyEvent->SourceProcessId,
            registrySetValueKeyEvent->SourceThreadId,
            registrySetValueKeyEvent->SourceProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            registrySetValueKeyEvent->KeyPath,
            registrySetValueKeyEvent->Type,
            registrySetValueKeyEvent->Data,
            registrySetValueKeyEvent->ValueName
        );

        //
        // Free the memory allocated for the event data
        //
        free(registrySetValueKeyEvent);
        break;

    }
    case 9:
    {
        printf("Registry Create Key Event\n");
        PRegistryCreateKeyEvent registryCreateKeyEvent = (PRegistryCreateKeyEvent)malloc(sizeof(RegistryCreateKeyEvent));
        if (registryCreateKeyEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for registryCreateKeyEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
        registryCreateKeyEvent->EventId = *(INT32*)propertyDataVector[0];
        registryCreateKeyEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        registryCreateKeyEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        registryCreateKeyEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        registryCreateKeyEvent->KeyPath = (WCHAR*)propertyDataVector[4];
        registryCreateKeyEvent->DesiredAccess = *(INT32*)propertyDataVector[5];
        registryCreateKeyEvent->EventTime = *(FILETIME*)propertyDataVector[6];

        FileTimeToSystemTime(&registryCreateKeyEvent->EventTime, &systemTime);

        PProcessInformation processInformation;
        processInformation = GetProcessName(registryCreateKeyEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }

        EventWriteRegistryCreateKey(
            &systemTime,
            processInformation->processName.c_str(),
            registryCreateKeyEvent->SourceProcessId,
            registryCreateKeyEvent->SourceThreadId,
            registryCreateKeyEvent->SourceProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            registryCreateKeyEvent->KeyPath
        );

        //
        // Free the memory allocated for the event data
        //
        free(registryCreateKeyEvent);
        break;
    }
    case 10:
    {
        printf("File Operation Event\n");
        PFileCreationEvent fileCreationEvent = (PFileCreationEvent)malloc(sizeof(FileCreationEvent));
        if (fileCreationEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for fileCreationEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
        fileCreationEvent->EventId = *(INT32*)propertyDataVector[0];
        fileCreationEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        fileCreationEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        fileCreationEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        fileCreationEvent->FileName = (WCHAR*)propertyDataVector[4];
        fileCreationEvent->EventTime = *(FILETIME*)propertyDataVector[5];

        FileTimeToSystemTime(&fileCreationEvent->EventTime, &systemTime);

        //
        // Filter: Check to see if ending of the file is .exe, .sys, .dll, .js, .vbs, .ps1, .bat, .cmd, .hta, .msi. Set all fileNames to lowercase before checking
        //
        std::wstring fileName = fileCreationEvent->FileName;
        std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::tolower);

        std::wregex validExtensions(LR"((\.exe|\.sys|\.dll|\.js|\.vbs|\.ps1|\.bat|\.cmd|\.hta|\.msi)$)");
        bool hasValidExtension = std::regex_search(fileName, validExtensions);

        if (!hasValidExtension) {
            free(fileCreationEvent);
            break;
        }

        PProcessInformation processInformation;
        processInformation = GetProcessName(fileCreationEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }


        EventWriteFileCreation(
            &systemTime,
            processInformation->processName.c_str(),
            fileCreationEvent->SourceProcessId,
            fileCreationEvent->SourceThreadId,
            fileCreationEvent->SourceProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            fileCreationEvent->FileName
        );

        //
        // Free the memory allocated for the event data
        //
        free(fileCreationEvent);
        break;
    }
    case 11:
    {
        printf("Named Pipe Creation Event\n");
        PNamedPipeCreateEvent namedPipeCreationEvent = (PNamedPipeCreateEvent)malloc(sizeof(NamedPipeCreateEvent));
        if (namedPipeCreationEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for namedPipeCreationEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
        namedPipeCreationEvent->EventId = *(INT32*)propertyDataVector[0];
        namedPipeCreationEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        namedPipeCreationEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        namedPipeCreationEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        namedPipeCreationEvent->FileName = (WCHAR*)propertyDataVector[4];
        namedPipeCreationEvent->RequestedRights = *(INT32*)propertyDataVector[5];
        namedPipeCreationEvent->GrantedRights = *(INT32*)propertyDataVector[6];
        namedPipeCreationEvent->EventTime = *(FILETIME*)propertyDataVector[7];

        FileTimeToSystemTime(&namedPipeCreationEvent->EventTime, &systemTime);

        PProcessInformation processInformation;
        processInformation = GetProcessName(namedPipeCreationEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }

        EventWriteNamedPipeCreation(
            &systemTime,
            processInformation->processName.c_str(),
            namedPipeCreationEvent->SourceProcessId,
            namedPipeCreationEvent->SourceThreadId,
            namedPipeCreationEvent->SourceProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            namedPipeCreationEvent->FileName,
            namedPipeCreationEvent->RequestedRights
        );


        //
        // Free the memory allocated for the event data
        //
        free(namedPipeCreationEvent);
        break;

    }
    case 12:
    {
        printf("Named Pipe Connection Event\n");
        PNamedPipeConnectionEvent namedPipeConnectionEvent = (PNamedPipeConnectionEvent)malloc(sizeof(NamedPipeConnectionEvent));
        if (namedPipeConnectionEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for namedPipeConnectionEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        namedPipeConnectionEvent->EventId = *(INT32*)propertyDataVector[0];
        namedPipeConnectionEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        namedPipeConnectionEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        namedPipeConnectionEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        namedPipeConnectionEvent->FileName = (WCHAR*)propertyDataVector[4];
        namedPipeConnectionEvent->RequestedRights = *(INT32*)propertyDataVector[5];
        namedPipeConnectionEvent->EventTime = *(FILETIME*)propertyDataVector[6];

        FileTimeToSystemTime(&namedPipeConnectionEvent->EventTime, &systemTime);

        PProcessInformation processInformation;
        processInformation = GetProcessName(namedPipeConnectionEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }

        EventWriteNamedPipeConnection(
            &systemTime,
            processInformation->processName.c_str(),
            namedPipeConnectionEvent->SourceProcessId,
            namedPipeConnectionEvent->SourceThreadId,
            namedPipeConnectionEvent->SourceProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            namedPipeConnectionEvent->FileName,
            namedPipeConnectionEvent->RequestedRights
        );

        //
        // Free the memory allocated for the event data
        //
        free(namedPipeConnectionEvent);
        break;
    }
    case 13:
    {
        printf("Mailslot Creation Event\n");
        PMailslotCreateEvent mailslotCreationEvent = (PMailslotCreateEvent)malloc(sizeof(MailslotCreateEvent));
        if (mailslotCreationEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for mailslotCreationEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        mailslotCreationEvent->EventId = *(INT32*)propertyDataVector[0];
        mailslotCreationEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        mailslotCreationEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        mailslotCreationEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        mailslotCreationEvent->FileName = (WCHAR*)propertyDataVector[4];
        mailslotCreationEvent->RequestedRights = *(INT32*)propertyDataVector[5];
        mailslotCreationEvent->EventTime = *(FILETIME*)propertyDataVector[6];

        FileTimeToSystemTime(&mailslotCreationEvent->EventTime, &systemTime);

        PProcessInformation processInformation;
        processInformation = GetProcessName(mailslotCreationEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }

        EventWriteMailslotCreation(
            &systemTime,
            processInformation->processName.c_str(),
            mailslotCreationEvent->SourceProcessId,
            mailslotCreationEvent->SourceThreadId,
            mailslotCreationEvent->SourceProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            mailslotCreationEvent->FileName,
            mailslotCreationEvent->RequestedRights
        );

        //
        // Free the memory allocated for the event data
        //
        free(mailslotCreationEvent);

    }
    case 14:
    {
        printf("Mailslot Connection Event\n");
        PMailslotConnectionEvent mailslotConnectionEvent = (PMailslotConnectionEvent)malloc(sizeof(MailslotConnectionEvent));
        if (mailslotConnectionEvent == nullptr) {
            OutputDebugString(L"Error allocating memory for mailslotConnectionEvent\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        mailslotConnectionEvent->EventId = *(INT32*)propertyDataVector[0];
        mailslotConnectionEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        mailslotConnectionEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        mailslotConnectionEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        mailslotConnectionEvent->FileName = (WCHAR*)propertyDataVector[4];
        mailslotConnectionEvent->RequestedRights = *(INT32*)propertyDataVector[5];
        mailslotConnectionEvent->EventTime = *(FILETIME*)propertyDataVector[6];

        FileTimeToSystemTime(&mailslotConnectionEvent->EventTime, &systemTime);

        PProcessInformation processInformation;
        processInformation = GetProcessName(mailslotConnectionEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }

        EventWriteMailslotConnection(
            &systemTime,
            processInformation->processName.c_str(),
            mailslotConnectionEvent->SourceProcessId,
            mailslotConnectionEvent->SourceThreadId,
            mailslotConnectionEvent->SourceProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            mailslotConnectionEvent->FileName,
            mailslotConnectionEvent->RequestedRights
        );


        //
        // Free the memory allocated for the event data
        //
        free(mailslotConnectionEvent);
        break;
    }
    case 15:
    {
        printf("Remote File Connection Event\n");
        PRemoteFileConnectionEvent remoteFileConnectionEvent = (PRemoteFileConnectionEvent)malloc(sizeof(RemoteFileConnectionEvent));
        remoteFileConnectionEvent->EventId = *(INT32*)propertyDataVector[0];
        remoteFileConnectionEvent->SourceThreadId = *(INT64*)propertyDataVector[1];
        remoteFileConnectionEvent->SourceProcessId = *(INT64*)propertyDataVector[2];
        remoteFileConnectionEvent->SourceProcessStartKey = *(UINT64*)propertyDataVector[3];
        remoteFileConnectionEvent->FileName = (WCHAR*)propertyDataVector[4];
        remoteFileConnectionEvent->EventTime = *(FILETIME*)propertyDataVector[5];

        FileTimeToSystemTime(&remoteFileConnectionEvent->EventTime, &systemTime);

        PProcessInformation processInformation;
        processInformation = GetProcessName(remoteFileConnectionEvent->SourceProcessId);
        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            printf("Process not found\n");
            break;
        }

        EventWriteRemoteFileConnection(
            &systemTime,
            processInformation->processName.c_str(),
            remoteFileConnectionEvent->SourceProcessId,
            remoteFileConnectionEvent->SourceThreadId,
            remoteFileConnectionEvent->SourceProcessStartKey,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            remoteFileConnectionEvent->FileName
        );

        //
        // Free the memory allocated for the event data
        //
        free(remoteFileConnectionEvent);
        break;
    }
    case 16:
    {
        std::wstring integirtyLevelString;
        OutputDebugStringW(L"Query - Thread Token Impersonation Event\n");
        PThreadImpersonationEvent threadImpersonationEvent = (PThreadImpersonationEvent)malloc(sizeof(ThreadImpersonationEvent));
        if (threadImpersonationEvent == nullptr) {
			OutputDebugString(L"Error allocating memory for threadImpersonationEvent\n");
			status = ERROR_NOT_ENOUGH_MEMORY;
			goto Exit;
		}
        threadImpersonationEvent->EventId = *(INT32*)propertyDataVector[0];
        threadImpersonationEvent->ThreadId = *(UINT32*)propertyDataVector[1];
        threadImpersonationEvent->ProcessId = *(UINT32*)propertyDataVector[2];
        threadImpersonationEvent->threadIntegrityLevel = *(UINT32*)propertyDataVector[3];
        threadImpersonationEvent->EventTime = *(SYSTEMTIME*)propertyDataVector[4];
        threadImpersonationEvent->ImpersonatedUser = (WCHAR*)propertyDataVector[5];

        switch(threadImpersonationEvent->threadIntegrityLevel) {
			case 12288:
                integirtyLevelString = L"High";
				break;
			case 16384:
                integirtyLevelString = L"System";
				break;
			default:
                free(threadImpersonationEvent);
                goto Exit;
		}

        PProcessInformation processInformation;
        processInformation = GetProcessName(threadImpersonationEvent->ProcessId);

        // Check if processInformation is not nullptr before dereferencing it
        if (processInformation == nullptr) {
            OutputDebugStringW(L"Query - Thread Token Impersonation Event Process Information Not Found\n");
            break;
        }

        EventWriteQueryTokenImpersonation(
            &threadImpersonationEvent->EventTime,
            processInformation->processName.c_str(),
            threadImpersonationEvent->ProcessId,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            threadImpersonationEvent->ThreadId,
            integirtyLevelString.c_str(),
            threadImpersonationEvent->ImpersonatedUser
        );

        //
        // Free the memory allocated for the event data
        //
        free(threadImpersonationEvent);
        break;
    }
    case 100:
    {
        printf("TraceLogging Provider Registered Event\n");
        PTraceLoggingProviderRegistered traceLoggingProviderRegistered = (PTraceLoggingProviderRegistered)malloc(sizeof(TraceLoggingProviderRegistered));
        traceLoggingProviderRegistered->EventId = *(INT32*)propertyDataVector[0];
        traceLoggingProviderRegistered->IsRegistered = *(BOOL*)propertyDataVector[1];

        printf("    EventId %d\n", traceLoggingProviderRegistered->EventId);
        printf("    IsRegistered: %s\n", traceLoggingProviderRegistered->IsRegistered ? "true" : "false");
        printf("\n");

        //
        // Free the memory allocated for the event data
        //
        free(traceLoggingProviderRegistered);

        break;
    }
    case 101:
    {
        printf("Event Schema Configuration Event\n");
        PEventSchemaConfiguration eventSchemaConfiguration = (PEventSchemaConfiguration)malloc(sizeof(EventSchemaConfiguration));
        eventSchemaConfiguration->EventId = *(INT32*)propertyDataVector[0];
        eventSchemaConfiguration->ProcessCreation = *(BOOL*)propertyDataVector[1];
        eventSchemaConfiguration->ProcessTermination = *(BOOL*)propertyDataVector[2];
        eventSchemaConfiguration->RegistryEvents = *(BOOL*)propertyDataVector[3];
        eventSchemaConfiguration->ProcessHandleCreation = *(BOOL*)propertyDataVector[4];
        eventSchemaConfiguration->ProcessHandleDuplication = *(BOOL*)propertyDataVector[5];
        eventSchemaConfiguration->RemoteThreadCreation = *(BOOL*)propertyDataVector[6];
        eventSchemaConfiguration->ImageLoad = *(BOOL*)propertyDataVector[7];
        eventSchemaConfiguration->ThreadImpersonationEvents_KM = *(BOOL*)propertyDataVector[8];
        eventSchemaConfiguration->FileEvents = *(BOOL*)propertyDataVector[9];

        printf("    EventId %d\n", eventSchemaConfiguration->EventId);
        printf("    ProcessCreation %s\n", eventSchemaConfiguration->ProcessCreation ? "true" : "false");
        printf("    ProcessTermination %s\n", eventSchemaConfiguration->ProcessTermination ? "true" : "false");
        printf("    RegistryEvents %s\n", eventSchemaConfiguration->RegistryEvents ? "true" : "false");
        printf("    ProcessHandleCreation %s\n", eventSchemaConfiguration->ProcessHandleCreation ? "true" : "false");
        printf("    ProcessHandleDuplication %s\n", eventSchemaConfiguration->ProcessHandleDuplication ? "true" : "false");
        printf("    RemoteThreadCreation %s\n", eventSchemaConfiguration->RemoteThreadCreation ? "true" : "false");
        printf("    ImageLoad %s\n", eventSchemaConfiguration->ImageLoad ? "true" : "false");
        printf("    ThreadImpersonationEvents_KM %s\n", eventSchemaConfiguration->ThreadImpersonationEvents_KM ? "true" : "false");
        printf("    FileEvents %s\n", eventSchemaConfiguration->FileEvents ? "true" : "false");
        printf("\n");
        //
        // Free the memory allocated for the event data
        //
        free(eventSchemaConfiguration);

        break;
    }
    case 102:
    {
        PDebugLog debugLog = (PDebugLog)malloc(sizeof(DebugLog));
        debugLog->EventId = *(INT32*)propertyDataVector[0];
        debugLog->ProcessProtection = *(BOOL*)propertyDataVector[1];

        OutputDebugString(L"Debug Log Event\n");
        OutputDebugString(L"    EventId: ");
        OutputDebugString(std::to_wstring(debugLog->EventId).c_str());
        OutputDebugString(L"\n");
        OutputDebugString(L"    ProcessProtection: ");
        OutputDebugString(debugLog->ProcessProtection ? L"true" : L"false");


        EventWriteDebugLog102(
            debugLog->EventId,
            debugLog->ProcessProtection
        );

        free(debugLog);

        break;
    }
    default:
    {
        break;
    }
    }

Exit:
    if (pInfo != nullptr) {
        free(pInfo);
    }

    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        for (int i = 0; i < vectorSize; i++) {
            if (propertyDataVector[i] != nullptr) {
                free(propertyDataVector[i]);
            }
        }
        free(propertyDataVector);
    }

    return status;

}


NTSTATUS WriteThreatIntelEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = NULL;
    SYSTEMTIME systemTime;
    BYTE** propertyDataVector = NULL;
    PProcessInformation callingProcessInformation;
    PProcessInformation targetProcessInformation;


    GetSystemTime(&systemTime);
    switch (EventHeader->EventDescriptor.Id) {
    case 1:
    {
        UINT32 CallingProcessId, CallingThreadId, TargetProcessId, OriginalProcessId, AllocationType, ProtectionMask;
        UINT64 CallingProcessStartKey, TargetProcessStartKey, OriginalProcessStartKey, BaseAddress, RegionSize;
        FILETIME CallingProcessCreationTime, CallingThreadCreationTime, TargetProcessCreateTime, OriginalProcessCreateTime;
        UINT8 CallingProcessSignatureLevel, CallingProcessSectionSignatureLevel, CallingProcessProtection, TargetProcessSignatureLevel, TargetProcessSectionSignatureLevel, TargetProcessProtection, OriginalProcessSignatureLevel, OriginalProcessProtection, OriginalProcessSectionSignatureLevel;

        status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (!pInfo) {
                OutputDebugString(L"Error allocating memory for event info\n");
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }
        if (status != ERROR_SUCCESS || pInfo == NULL) {
            OutputDebugString(L"Error fetching event info\n");
            return status;
        }

        //
        // Allocate memory for property data vector
        //
        propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
        if (!propertyDataVector) {
            OutputDebugString(L"Error allocating memory for propertyDataVector\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error processing ETW event\n");
            goto Exit;
        }

        CallingProcessId = *(UINT32*)propertyDataVector[0];
        CallingProcessCreationTime = *(FILETIME*)propertyDataVector[1];
        CallingProcessStartKey = *(UINT64*)propertyDataVector[2];
        CallingProcessSignatureLevel = *(UINT8*)propertyDataVector[3];
        CallingProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[4];
        CallingProcessProtection = *(UINT8*)propertyDataVector[5];
        CallingThreadId = *(UINT32*)propertyDataVector[6];
        CallingThreadCreationTime = *(FILETIME*)propertyDataVector[7];
        TargetProcessId = *(UINT32*)propertyDataVector[8];
        TargetProcessCreateTime = *(FILETIME*)propertyDataVector[9];
        TargetProcessStartKey = *(UINT64*)propertyDataVector[10];
        TargetProcessSignatureLevel = *(UINT8*)propertyDataVector[11];
        TargetProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[12];
        TargetProcessProtection = *(UINT8*)propertyDataVector[13];
        OriginalProcessId = *(UINT32*)propertyDataVector[14];
        OriginalProcessCreateTime = *(FILETIME*)propertyDataVector[15];
        OriginalProcessStartKey = *(UINT64*)propertyDataVector[16];
        OriginalProcessSignatureLevel = *(UINT8*)propertyDataVector[17];
        OriginalProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[18];
        OriginalProcessProtection = *(UINT8*)propertyDataVector[19];
        BaseAddress = *(UINT64*)propertyDataVector[20];
        RegionSize = *(UINT64*)propertyDataVector[21];
        AllocationType = *(UINT32*)propertyDataVector[22];
        ProtectionMask = *(UINT32*)propertyDataVector[23];

        if (CallingProcessId == TargetProcessId)
        {
            goto Exit;
        }

        callingProcessInformation = GetProcessName(CallingProcessId);
        if (callingProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        targetProcessInformation = GetProcessName(TargetProcessId);
        if (targetProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        EventWriteRemoteVirtualAllocation(
            &systemTime,
            callingProcessInformation->processName.c_str(),
            callingProcessInformation->processId,
            callingProcessInformation->userName.c_str(),
            callingProcessInformation->authenticationId.LowPart,
            callingProcessInformation->integrityLevel.c_str(),
            callingProcessInformation->sessionId,
            CallingThreadId,
            targetProcessInformation->processName.c_str(),
            targetProcessInformation->processId,
            targetProcessInformation->userName.c_str(),
            targetProcessInformation->authenticationId.LowPart,
            targetProcessInformation->integrityLevel.c_str(),
            targetProcessInformation->sessionId,
            CallingProcessStartKey,
            TargetProcessStartKey,
            BaseAddress
        );

        goto Exit;
    }
    case 4:
    {
        UINT32 CallingProcessId, CallingThreadId, TargetProcessId, OriginalProcessId, TargetThreadId;
        UINT64 CallingProcessStartKey, TargetProcessStartKey, OriginalProcessStartKey, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3;
        FILETIME CallingProcessCreationTime, CallingThreadCreationTime, TargetProcessCreateTime, OriginalProcessCreateTime, RealEventTime, TargetThreadCreateTime;
        UINT8 CallingProcessSignatureLevel, CallingProcessSectionSignatureLevel, CallingProcessProtection, TargetProcessSignatureLevel, TargetProcessSectionSignatureLevel, TargetProcessProtection, OriginalProcessSignatureLevel, OriginalProcessProtection, OriginalProcessSectionSignatureLevel, TargetThreadAlertable;

        status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (!pInfo) {
                OutputDebugString(L"Error allocating memory for event info\n");
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error fetching event info\n");
            return status;
        }

        //
        // Allocate memory for property data vector
        //
        propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
        if (!propertyDataVector) {
            OutputDebugString(L"Error allocating memory for propertyDataVector\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error processing ETW event\n");
            goto Exit;
        }

        CallingProcessId = *(UINT32*)propertyDataVector[0];
        CallingProcessCreationTime = *(FILETIME*)propertyDataVector[1];
        CallingProcessStartKey = *(UINT64*)propertyDataVector[2];
        CallingProcessSignatureLevel = *(UINT8*)propertyDataVector[3];
        CallingProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[4];
        CallingProcessProtection = *(UINT8*)propertyDataVector[5];
        CallingThreadId = *(UINT32*)propertyDataVector[6];
        CallingThreadCreationTime = *(FILETIME*)propertyDataVector[7];
        TargetProcessId = *(UINT32*)propertyDataVector[8];
        TargetProcessCreateTime = *(FILETIME*)propertyDataVector[9];
        TargetProcessStartKey = *(UINT64*)propertyDataVector[10];
        TargetProcessSignatureLevel = *(UINT8*)propertyDataVector[11];
        TargetProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[12];
        TargetProcessProtection = *(UINT8*)propertyDataVector[13];
        TargetThreadId = *(UINT32*)propertyDataVector[14];
        TargetThreadCreateTime = *(FILETIME*)propertyDataVector[15];
        OriginalProcessId = *(UINT32*)propertyDataVector[16];
        OriginalProcessCreateTime = *(FILETIME*)propertyDataVector[17];
        OriginalProcessStartKey = *(UINT64*)propertyDataVector[18];
        OriginalProcessSignatureLevel = *(UINT8*)propertyDataVector[19];
        OriginalProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[20];
        OriginalProcessProtection = *(UINT8*)propertyDataVector[21];
        TargetThreadAlertable = *(UINT8*)propertyDataVector[22];
        ApcRoutine = *(UINT64*)propertyDataVector[23];
        ApcArgument1 = *(UINT64*)propertyDataVector[24];
        ApcArgument2 = *(UINT64*)propertyDataVector[25];
        ApcArgument3 = *(UINT64*)propertyDataVector[26];
        RealEventTime = *(FILETIME*)propertyDataVector[27];



        callingProcessInformation = GetProcessName(CallingProcessId);
        if (callingProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        targetProcessInformation = GetProcessName(TargetProcessId);
        if (targetProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        EventWriteRemoteQueueUserAPC(
            &systemTime,
            callingProcessInformation->processName.c_str(),
            callingProcessInformation->processId,
            callingProcessInformation->userName.c_str(),
            callingProcessInformation->authenticationId.LowPart,
            callingProcessInformation->integrityLevel.c_str(),
            callingProcessInformation->sessionId,
            CallingThreadId,
            targetProcessInformation->processName.c_str(),
            targetProcessInformation->processId,
            targetProcessInformation->userName.c_str(),
            targetProcessInformation->authenticationId.LowPart,
            targetProcessInformation->integrityLevel.c_str(),
            targetProcessInformation->sessionId,
            CallingProcessStartKey,
            TargetProcessStartKey,
            ApcRoutine,
            ApcArgument1,
            ApcArgument2,
            ApcArgument3
        );

        goto Exit;
    }
    case 13:
    {
        //
        // check to see if there is a second between lastEventTime and systemTime
        //
        if (systemTime.wSecond - lastEventTime.wSecond < 1) {
            goto Exit;
        }
        lastEventTime = systemTime;

        UINT32 OperationStatus, CallingProcessId, CallingThreadId, TargetProcessId;
        FILETIME CallingProcessCreateTime, CallingThreadCreateTime, TargetProcessCreateTime;
        UINT64 CallingProcessStartKey, TargetProcessStartKey, BaseAddress, BytesCopied;
        UINT8 CallingProcessSignatureLevel, CallingProcessSectionSignatureLevel, CallingProcessProtection, TargetProcessSignatureLevel, TargetProcessSectionSignatureLevel, TargetProcessProtection;

        status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (!pInfo) {
                OutputDebugString(L"Error allocating memory for event info\n");
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error fetching event info\n");
            return status;
        }

        //
        // Allocate memory for property data vector
        //
        propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
        if (!propertyDataVector) {
            OutputDebugString(L"Error allocating memory for propertyDataVector\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error processing ETW event\n");
            goto Exit;
        }

        OperationStatus = *(UINT32*)propertyDataVector[0];
        CallingProcessId = *(UINT32*)propertyDataVector[1];
        CallingProcessCreateTime = *(FILETIME*)propertyDataVector[2];
        CallingProcessStartKey = *(UINT64*)propertyDataVector[3];
        CallingProcessSignatureLevel = *(UINT8*)propertyDataVector[4];
        CallingProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[5];
        CallingProcessProtection = *(UINT8*)propertyDataVector[6];
        CallingThreadId = *(UINT32*)propertyDataVector[7];
        CallingThreadCreateTime = *(FILETIME*)propertyDataVector[8];
        TargetProcessId = *(UINT32*)propertyDataVector[9];
        TargetProcessCreateTime = *(FILETIME*)propertyDataVector[10];
        TargetProcessStartKey = *(UINT64*)propertyDataVector[11];
        TargetProcessSignatureLevel = *(UINT8*)propertyDataVector[12];
        TargetProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[13];
        TargetProcessProtection = *(UINT8*)propertyDataVector[14];
        BaseAddress = *(UINT64*)propertyDataVector[15];
        BytesCopied = *(UINT64*)propertyDataVector[16];

        if (TargetProcessId != lsassPID)
        {
            goto Exit;
        }

        callingProcessInformation = GetProcessName(CallingProcessId);
        if (callingProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        targetProcessInformation = GetProcessName(TargetProcessId);
        if (targetProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        EventWriteRemoteReadProcessMemory(
            &systemTime,
            callingProcessInformation->processName.c_str(),
            callingProcessInformation->processId,
            callingProcessInformation->userName.c_str(),
            callingProcessInformation->authenticationId.LowPart,
            callingProcessInformation->integrityLevel.c_str(),
            callingProcessInformation->sessionId,
            CallingThreadId,
            targetProcessInformation->processName.c_str(),
            targetProcessInformation->processId,
            targetProcessInformation->userName.c_str(),
            targetProcessInformation->authenticationId.LowPart,
            targetProcessInformation->integrityLevel.c_str(),
            targetProcessInformation->sessionId,
            CallingProcessStartKey,
            TargetProcessStartKey
        );




        goto Exit;
    }
    case 14:
    {
        UINT32 OperationStatus, CallingProcessId, CallingThreadId, TargetProcessId;
        FILETIME CallingProcessCreateTime, CallingThreadCreateTime, TargetProcessCreateTime;
        UINT64 CallingProcessStartKey, TargetProcessStartKey, BaseAddress, BytesCopied;
        UINT8 CallingProcessSignatureLevel, CallingProcessSectionSignatureLevel, CallingProcessProtection, TargetProcessSignatureLevel, TargetProcessSectionSignatureLevel, TargetProcessProtection;

        status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (!pInfo) {
                OutputDebugString(L"Error allocating memory for event info\n");
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error fetching event info\n");
            return status;
        }

        //
        // Allocate memory for property data vector
        //
        propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
        if (!propertyDataVector) {
            OutputDebugString(L"Error allocating memory for propertyDataVector\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error processing ETW event\n");
            goto Exit;
        }

        OperationStatus = *(UINT32*)propertyDataVector[0];
        CallingProcessId = *(UINT32*)propertyDataVector[1];
        CallingProcessCreateTime = *(FILETIME*)propertyDataVector[2];
        CallingProcessStartKey = *(UINT64*)propertyDataVector[3];
        CallingProcessSignatureLevel = *(UINT8*)propertyDataVector[4];
        CallingProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[5];
        CallingProcessProtection = *(UINT8*)propertyDataVector[6];
        CallingThreadId = *(UINT32*)propertyDataVector[7];
        CallingThreadCreateTime = *(FILETIME*)propertyDataVector[8];
        TargetProcessId = *(UINT32*)propertyDataVector[9];
        TargetProcessCreateTime = *(FILETIME*)propertyDataVector[10];
        TargetProcessStartKey = *(UINT64*)propertyDataVector[11];
        TargetProcessSignatureLevel = *(UINT8*)propertyDataVector[12];
        TargetProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[13];
        TargetProcessProtection = *(UINT8*)propertyDataVector[14];
        BaseAddress = *(UINT64*)propertyDataVector[15];
        BytesCopied = *(UINT64*)propertyDataVector[16];


        callingProcessInformation = GetProcessName(CallingProcessId);
        if (callingProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        targetProcessInformation = GetProcessName(TargetProcessId);
        if (targetProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        EventWriteRemoteWriteProcessMemory(
            &systemTime,
            callingProcessInformation->processName.c_str(),
            callingProcessInformation->processId,
            callingProcessInformation->userName.c_str(),
            callingProcessInformation->authenticationId.LowPart,
            callingProcessInformation->integrityLevel.c_str(),
            callingProcessInformation->sessionId,
            CallingThreadId,
            targetProcessInformation->processName.c_str(),
            targetProcessInformation->processId,
            targetProcessInformation->userName.c_str(),
            targetProcessInformation->authenticationId.LowPart,
            targetProcessInformation->integrityLevel.c_str(),
            targetProcessInformation->sessionId,
            CallingProcessStartKey,
            TargetProcessStartKey
        );

        goto Exit;
    }
    case 21:
    {
        UINT32 CallingProcessId, CallingThreadId, TargetProcessId, OriginalProcessId, AllocationType, ProtectionMask;
        UINT64 CallingProcessStartKey, TargetProcessStartKey, OriginalProcessStartKey, BaseAddress, RegionSize;
        FILETIME CallingProcessCreationTime, CallingThreadCreationTime, TargetProcessCreateTime, OriginalProcessCreateTime;
        UINT8 CallingProcessSignatureLevel, CallingProcessSectionSignatureLevel, CallingProcessProtection, TargetProcessSignatureLevel, TargetProcessSectionSignatureLevel, TargetProcessProtection, OriginalProcessSignatureLevel, OriginalProcessProtection, OriginalProcessSectionSignatureLevel;

        status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (!pInfo) {
                OutputDebugString(L"Error allocating memory for event info\n");
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error fetching event info\n");
            return status;
        }

        //
        // Allocate memory for property data vector
        //
        propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
        if (!propertyDataVector) {
            OutputDebugString(L"Error allocating memory for propertyDataVector\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error processing ETW event\n");
            goto Exit;
        }

        CallingProcessId = *(UINT32*)propertyDataVector[0];
        CallingProcessCreationTime = *(FILETIME*)propertyDataVector[1];
        CallingProcessStartKey = *(UINT64*)propertyDataVector[2];
        CallingProcessSignatureLevel = *(UINT8*)propertyDataVector[3];
        CallingProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[4];
        CallingProcessProtection = *(UINT8*)propertyDataVector[5];
        CallingThreadId = *(UINT32*)propertyDataVector[6];
        CallingThreadCreationTime = *(FILETIME*)propertyDataVector[7];
        TargetProcessId = *(UINT32*)propertyDataVector[8];
        TargetProcessCreateTime = *(FILETIME*)propertyDataVector[9];
        TargetProcessStartKey = *(UINT64*)propertyDataVector[10];
        TargetProcessSignatureLevel = *(UINT8*)propertyDataVector[11];
        TargetProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[12];
        TargetProcessProtection = *(UINT8*)propertyDataVector[13];
        OriginalProcessId = *(UINT32*)propertyDataVector[14];
        OriginalProcessCreateTime = *(FILETIME*)propertyDataVector[15];
        OriginalProcessStartKey = *(UINT64*)propertyDataVector[16];
        OriginalProcessSignatureLevel = *(UINT8*)propertyDataVector[17];
        OriginalProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[18];
        OriginalProcessProtection = *(UINT8*)propertyDataVector[19];
        BaseAddress = *(UINT64*)propertyDataVector[20];
        RegionSize = *(UINT64*)propertyDataVector[21];
        AllocationType = *(UINT32*)propertyDataVector[22];
        ProtectionMask = *(UINT32*)propertyDataVector[23];

        if (CallingProcessId == TargetProcessId)
        {
            goto Exit;
        }

        callingProcessInformation = GetProcessName(CallingProcessId);
        if (callingProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        targetProcessInformation = GetProcessName(TargetProcessId);
        if (targetProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        EventWriteRemoteReadProcessMemory(
            &systemTime,
            callingProcessInformation->processName.c_str(),
            callingProcessInformation->processId,
            callingProcessInformation->userName.c_str(),
            callingProcessInformation->authenticationId.LowPart,
            callingProcessInformation->integrityLevel.c_str(),
            callingProcessInformation->sessionId,
            CallingThreadId,
            targetProcessInformation->processName.c_str(),
            targetProcessInformation->processId,
            targetProcessInformation->userName.c_str(),
            targetProcessInformation->authenticationId.LowPart,
            targetProcessInformation->integrityLevel.c_str(),
            targetProcessInformation->sessionId,
            CallingProcessStartKey,
            TargetProcessStartKey
        );

        goto Exit;
    }
    case 24:
    {
        UINT32 CallingProcessId, CallingThreadId, TargetProcessId, OriginalProcessId, TargetThreadId;
        UINT64 CallingProcessStartKey, TargetProcessStartKey, OriginalProcessStartKey, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3;
        FILETIME CallingProcessCreationTime, CallingThreadCreationTime, TargetProcessCreateTime, OriginalProcessCreateTime, RealEventTime, TargetThreadCreateTime;
        UINT8 CallingProcessSignatureLevel, CallingProcessSectionSignatureLevel, CallingProcessProtection, TargetProcessSignatureLevel, TargetProcessSectionSignatureLevel, TargetProcessProtection, OriginalProcessSignatureLevel, OriginalProcessProtection, OriginalProcessSectionSignatureLevel, TargetThreadAlertable;

        status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (!pInfo) {
                OutputDebugString(L"Error allocating memory for event info\n");
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error fetching event info\n");
            return status;
        }

        //
        // Allocate memory for property data vector
        //
        propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
        if (!propertyDataVector) {
            OutputDebugString(L"Error allocating memory for propertyDataVector\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error processing ETW event\n");
            goto Exit;
        }

        CallingProcessId = *(UINT32*)propertyDataVector[0];
        CallingProcessCreationTime = *(FILETIME*)propertyDataVector[1];
        CallingProcessStartKey = *(UINT64*)propertyDataVector[2];
        CallingProcessSignatureLevel = *(UINT8*)propertyDataVector[3];
        CallingProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[4];
        CallingProcessProtection = *(UINT8*)propertyDataVector[5];
        CallingThreadId = *(UINT32*)propertyDataVector[6];
        CallingThreadCreationTime = *(FILETIME*)propertyDataVector[7];
        TargetProcessId = *(UINT32*)propertyDataVector[8];
        TargetProcessCreateTime = *(FILETIME*)propertyDataVector[9];
        TargetProcessStartKey = *(UINT64*)propertyDataVector[10];
        TargetProcessSignatureLevel = *(UINT8*)propertyDataVector[11];
        TargetProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[12];
        TargetProcessProtection = *(UINT8*)propertyDataVector[13];
        TargetThreadId = *(UINT32*)propertyDataVector[14];
        TargetThreadCreateTime = *(FILETIME*)propertyDataVector[15];
        OriginalProcessId = *(UINT32*)propertyDataVector[16];
        OriginalProcessCreateTime = *(FILETIME*)propertyDataVector[17];
        OriginalProcessStartKey = *(UINT64*)propertyDataVector[18];
        OriginalProcessSignatureLevel = *(UINT8*)propertyDataVector[19];
        OriginalProcessSectionSignatureLevel = *(UINT8*)propertyDataVector[20];
        OriginalProcessProtection = *(UINT8*)propertyDataVector[21];
        TargetThreadAlertable = *(UINT8*)propertyDataVector[22];
        ApcRoutine = *(UINT64*)propertyDataVector[23];
        ApcArgument1 = *(UINT64*)propertyDataVector[24];
        ApcArgument2 = *(UINT64*)propertyDataVector[25];
        ApcArgument3 = *(UINT64*)propertyDataVector[26];
        RealEventTime = *(FILETIME*)propertyDataVector[27];



        callingProcessInformation = GetProcessName(CallingProcessId);
        if (callingProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        targetProcessInformation = GetProcessName(TargetProcessId);
        if (targetProcessInformation == nullptr) {
            OutputDebugString(L"ThreatIntel ETW - Error getting process name\n");
            goto Exit;
        }

        EventWriteRemoteQueueUserAPC(
            &systemTime,
            callingProcessInformation->processName.c_str(),
            callingProcessInformation->processId,
            callingProcessInformation->userName.c_str(),
            callingProcessInformation->authenticationId.LowPart,
            callingProcessInformation->integrityLevel.c_str(),
            callingProcessInformation->sessionId,
            CallingThreadId,
            targetProcessInformation->processName.c_str(),
            targetProcessInformation->processId,
            targetProcessInformation->userName.c_str(),
            targetProcessInformation->authenticationId.LowPart,
            targetProcessInformation->integrityLevel.c_str(),
            targetProcessInformation->sessionId,
            CallingProcessStartKey,
            TargetProcessStartKey,
            ApcRoutine,
            ApcArgument1,
            ApcArgument2,
            ApcArgument3
        );

        goto Exit;
    }
    default:
    {
        goto Exit;
    }
    }
Exit:

    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            if (propertyDataVector[i] != nullptr) {
                free(propertyDataVector[i]);
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return 0;
}


BOOL WriteNetworkEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = nullptr;
    BYTE** propertyDataVector = nullptr;
    int vectorCapacity = 10;
    int vectorSize = 0;
    SYSTEMTIME systemTime;
    UINT32 processId, size, sourceAddress, destinationAddress;
    UINT16 sourcePort, destinationPort;
    PProcessInformation processInformation;
    WCHAR wide_deststring_ip[INET_ADDRSTRLEN];
    WCHAR wide_sourcestring_ip[INET_ADDRSTRLEN];
    struct in_addr srceaddr = {};
    struct in_addr destaddr = {};
    BOOL isInitiated = false;

    switch (EventHeader->EventDescriptor.Id) {
    case 10:
    {
        isInitiated = true;

        //
       // Get System Time
       //
        GetSystemTime(&systemTime);

        // Fetch initial event information size
        status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (!pInfo) {
                OutputDebugString(L"Error allocating memory for event info\n");
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error fetching event info\n");
            return status;
        }

        // Allocate memory for property data vector
        propertyDataVector = (BYTE**)malloc(vectorCapacity * sizeof(BYTE*));
        if (!propertyDataVector) {
            OutputDebugString(L"Error allocating memory for propertyDataVector\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        // Process each property in the event
        for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            PROPERTY_DATA_DESCRIPTOR dataDescriptor;
            DWORD propertySize = 0;
            WCHAR* propertyName = (WCHAR*)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
            dataDescriptor.PropertyName = (ULONGLONG)propertyName;
            dataDescriptor.ArrayIndex = ULONG_MAX;

            // Determine the size of the property
            status = TdhGetPropertySize(EventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
            if (status != ERROR_SUCCESS) {
                wprintf(L"Error getting size for property %ls\n", propertyName);
                goto Exit;
            }

            BYTE* propertyData = (BYTE*)malloc(propertySize);
            if (!propertyData) {
                wprintf(L"Error allocating memory for property %ls\n", propertyName);
                goto Exit;
            }

            // Get the actual property data
            status = TdhGetProperty(EventRecord, 0, NULL, 1, &dataDescriptor, propertySize, propertyData);
            if (status != ERROR_SUCCESS) {
                wprintf(L"Error getting data for property %ls\n", propertyName);
                goto Exit;
            }

            // Check if we need to resize the vector
            if (vectorSize == vectorCapacity) {
                BYTE** resizedVector = (BYTE**)realloc(propertyDataVector, 2 * vectorCapacity * sizeof(BYTE*));
                if (!resizedVector) {
                    OutputDebugString(L"Error resizing propertyDataVector\n");
                    goto Exit;
                }
                propertyDataVector = resizedVector;
                vectorCapacity *= 2;
            }

            // Add the data to the vector
            propertyDataVector[vectorSize++] = propertyData;
        }

        processId = *(UINT32*)propertyDataVector[0];

        if (processId == 4)
        {
            goto Exit;
        }

        size = *(UINT32*)propertyDataVector[1];
        destinationAddress = *(UINT32*)propertyDataVector[2];
        sourceAddress = *(UINT32*)propertyDataVector[3];
        sourcePort = *(UINT16*)propertyDataVector[4];
        destinationPort = *(UINT16*)propertyDataVector[5];

        destaddr.s_addr = destinationAddress;
        srceaddr.s_addr = sourceAddress;

        InetNtop(AF_INET, &srceaddr, wide_sourcestring_ip, INET_ADDRSTRLEN);
        InetNtop(AF_INET, &destaddr, wide_deststring_ip, INET_ADDRSTRLEN);


        processInformation = GetProcessName(processId);
        if (processInformation == nullptr) {
            OutputDebugString(L"DotNet ETW - Error getting process name\n");
            goto Exit;
        }

        if (processInformation->integrityLevel == L"Low")
        {
            goto Exit;
        }

        EventWriteNetworkConnection(
            &systemTime,
            processId,
            processInformation->processName.c_str(),
            wide_sourcestring_ip,
            wide_deststring_ip,
            sourcePort,
            destinationPort,
            isInitiated,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId
        );

        break;
    }
    case 11:
    {
        //
       // Get System Time
       //
        GetSystemTime(&systemTime);

        // Fetch initial event information size
        status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
        if (status == ERROR_INSUFFICIENT_BUFFER) {
            pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
            if (!pInfo) {
                OutputDebugString(L"Error allocating memory for event info\n");
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
            status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
        }
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error fetching event info\n");
            return status;
        }

        // Allocate memory for property data vector
        propertyDataVector = (BYTE**)malloc(vectorCapacity * sizeof(BYTE*));
        if (!propertyDataVector) {
            OutputDebugString(L"Error allocating memory for propertyDataVector\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }

        // Process each property in the event
        for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            PROPERTY_DATA_DESCRIPTOR dataDescriptor;
            DWORD propertySize = 0;
            WCHAR* propertyName = (WCHAR*)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
            dataDescriptor.PropertyName = (ULONGLONG)propertyName;
            dataDescriptor.ArrayIndex = ULONG_MAX;

            // Determine the size of the property
            status = TdhGetPropertySize(EventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
            if (status != ERROR_SUCCESS) {
                wprintf(L"Error getting size for property %ls\n", propertyName);
                goto Exit;
            }

            BYTE* propertyData = (BYTE*)malloc(propertySize);
            if (!propertyData) {
                wprintf(L"Error allocating memory for property %ls\n", propertyName);
                goto Exit;
            }

            // Get the actual property data
            status = TdhGetProperty(EventRecord, 0, NULL, 1, &dataDescriptor, propertySize, propertyData);
            if (status != ERROR_SUCCESS) {
                wprintf(L"Error getting data for property %ls\n", propertyName);
                goto Exit;
            }

            // Check if we need to resize the vector
            if (vectorSize == vectorCapacity) {
                BYTE** resizedVector = (BYTE**)realloc(propertyDataVector, 2 * vectorCapacity * sizeof(BYTE*));
                if (!resizedVector) {
                    OutputDebugString(L"Error resizing propertyDataVector\n");
                    goto Exit;
                }
                propertyDataVector = resizedVector;
                vectorCapacity *= 2;
            }

            // Add the data to the vector
            propertyDataVector[vectorSize++] = propertyData;
        }

        processId = *(UINT32*)propertyDataVector[0];

        if (processId == 4)
        {
            goto Exit;
        }

        size = *(UINT32*)propertyDataVector[1];
        destinationAddress = *(UINT32*)propertyDataVector[2];
        sourceAddress = *(UINT32*)propertyDataVector[3];
        sourcePort = *(UINT16*)propertyDataVector[4];
        destinationPort = *(UINT16*)propertyDataVector[5];

        destaddr.s_addr = sourceAddress;
        srceaddr.s_addr = destinationAddress;

        InetNtop(AF_INET, &srceaddr, wide_sourcestring_ip, INET_ADDRSTRLEN);
        InetNtop(AF_INET, &destaddr, wide_deststring_ip, INET_ADDRSTRLEN);

        processInformation = GetProcessName(processId);
        if (processInformation == nullptr) {
            OutputDebugString(L"DotNet ETW - Error getting process name\n");
            goto Exit;
        }

        if (processInformation->integrityLevel == L"Low")
        {
            goto Exit;
        }

        EventWriteNetworkConnection(
            &systemTime,
            processId,
            processInformation->processName.c_str(),
            wide_sourcestring_ip,
            wide_deststring_ip,
            sourcePort,
            destinationPort,
            isInitiated,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId
        );



        break;
    }
    default:
    {
        break;
    }

    }

Exit:
    if (pInfo != nullptr) {
        free(pInfo);
    }

    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        for (int i = 0; i < vectorSize; i++) {
            if (propertyDataVector[i] != nullptr) {
                free(propertyDataVector[i]);
            }
        }
        free(propertyDataVector);
    }

    return status;
}

NTSTATUS ProcessEtwEvent(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PTRACE_EVENT_INFO PropertyInfo,
    _In_ BYTE** EventData
) {
    NTSTATUS status = ERROR_SUCCESS;
    int vectorSize = 0;


    // Process each property in the event
    for (ULONG i = 0; i < PropertyInfo->TopLevelPropertyCount; i++) {
        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
        DWORD propertySize = 0;
        WCHAR* propertyName = (WCHAR*)((BYTE*)PropertyInfo + PropertyInfo->EventPropertyInfoArray[i].NameOffset);
        dataDescriptor.PropertyName = (ULONGLONG)propertyName;
        dataDescriptor.ArrayIndex = ULONG_MAX;

        // Determine the size of the property
        status = TdhGetPropertySize(EventRecord, 0, NULL, 1, &dataDescriptor, &propertySize);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error getting size for property\n");
            goto Exit;
        }

        BYTE* propertyData = (BYTE*)malloc(propertySize);
        if (!propertyData) {
            OutputDebugString(L" Error allocating memory for propertyData\n");
            goto Exit;
        }

        // Get the actual property data
        status = TdhGetProperty(EventRecord, 0, NULL, 1, &dataDescriptor, propertySize, propertyData);
        if (status != ERROR_SUCCESS) {
            OutputDebugString(L"Error getting data for property\n");
            goto Exit;
        }

        //
        // Add the data to the vector
        //
        EventData[vectorSize++] = propertyData;

        if (vectorSize > PropertyInfo->TopLevelPropertyCount) {
            OutputDebugString(L"Error: vectorSize exceeded allocated EventData size\n");
            status = ERROR_BUFFER_OVERFLOW;
            goto Exit;
        }
    }

Exit:
    if (status != ERROR_SUCCESS) {
        for (int i = 0; i < vectorSize; i++) {
            if (EventData[i] != nullptr) {
                free(EventData[i]);
            }
        }
        free(EventData);
    }
    return status;

}


BOOL WriteAMSIEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {

    ULONG64 Session;
    UINT8 ScanStatus;
    UINT32 ScanResult, ContentSize, OriginalSize;
    std::wstring AppName, ContentName, decodedString;
    BYTE* Content;

    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = NULL;
    SYSTEMTIME systemTime;
    BYTE** propertyDataVector = NULL;
    PProcessInformation processInformation;
    GetSystemTime(&systemTime);

    //
    // Fetch initial event information size
    //
    status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (!pInfo) {
            OutputDebugString(L"Error allocating memory for event info\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
        status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
    }
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error fetching event info\n");
        return status;
    }

    //
    // Allocate memory for property data vector
    //
    propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
    if (!propertyDataVector) {
        OutputDebugString(L"Error allocating memory for propertyDataVector\n");
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto Exit;
    }

    status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error processing ETW event\n");
        goto Exit;
    }

    Session = *(ULONG64*)propertyDataVector[0];
    ScanStatus = *(UINT8*)propertyDataVector[1];
    ScanResult = *(UINT32*)propertyDataVector[2];
    AppName = (WCHAR*)propertyDataVector[3];

    if (AppName != L"VBScript" && AppName != L"JScript" && AppName != L"OFFICE_VBA" && AppName != L"Excel" && AppName != L"Excel.exe")
    {
        goto Exit;
    }

    ContentName = (WCHAR*)propertyDataVector[4];
    ContentSize = *(UINT32*)propertyDataVector[5];
    OriginalSize = *(UINT32*)propertyDataVector[6];
    Content = (BYTE*)propertyDataVector[7];

    if (ScanResult != (UINT32)1 && ScanResult != (UINT32)32768) {
        goto Exit;
    }

    processInformation = GetProcessName(EventHeader->ProcessId);
    if (processInformation == nullptr) {
        OutputDebugString(L"AMSI - Error getting process name\n");
        goto Exit;
    }

    decodedString = std::wstring(reinterpret_cast<const wchar_t*>(Content), ContentSize / sizeof(wchar_t));

    EventWriteAMSI(
        &systemTime,
        processInformation->processName.c_str(),
        processInformation->processId,
        processInformation->userName.c_str(),
        processInformation->authenticationId.LowPart,
        processInformation->integrityLevel.c_str(),
        processInformation->sessionId,
        AppName.c_str(),
        ContentName.c_str(),
        ScanStatus,
        ScanResult,
        ContentSize,
        Content,
        decodedString.c_str()
    );

Exit:
    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            if (propertyDataVector[i] != nullptr) {
                free(propertyDataVector[i]);
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }



    return TRUE;
}


NTSTATUS WriteDotNetEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {

    UINT64 AssemblyID, AppDomainID, BindingID;
    UINT32 AssemblyFlags;
    UINT16 ClrInstanceID;
    std::wstring FQAN;

    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = NULL;
    SYSTEMTIME systemTime;
    BYTE** propertyDataVector = NULL;
    PProcessInformation processInformation;
    GetSystemTime(&systemTime);

    //
    // Fetch initial event information size
    //
    status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (!pInfo) {
            OutputDebugString(L"Error allocating memory for event info\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
        status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
    }
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error fetching event info\n");
        return status;
    }

    //
    // Allocate memory for property data vector
    //
    propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
    if (!propertyDataVector) {
        OutputDebugString(L"Error allocating memory for propertyDataVector\n");
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto Exit;
    }

    status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error processing ETW event\n");
        goto Exit;
    }

    AssemblyID = *(UINT64*)propertyDataVector[0];
    AppDomainID = *(UINT64*)propertyDataVector[1];
    BindingID = *(UINT64*)propertyDataVector[2];
    AssemblyFlags = *(UINT32*)propertyDataVector[3];
    FQAN = (WCHAR*)propertyDataVector[4];
    ClrInstanceID = *(UINT16*)propertyDataVector[5];


    processInformation = GetProcessName(EventHeader->ProcessId);
    if (processInformation == nullptr) {
        OutputDebugString(L"DotNet ETW - Error getting process name\n");
        goto Exit;
    }

    EventWriteDotNetLoad(
        &systemTime,
        processInformation->processName.c_str(),
        processInformation->processId,
        processInformation->userName.c_str(),
        processInformation->authenticationId.LowPart,
        processInformation->integrityLevel.c_str(),
        processInformation->sessionId,
        FQAN.c_str(),
        ClrInstanceID
    );

Exit:
    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            if (propertyDataVector[i] != nullptr) {
                free(propertyDataVector[i]);
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }


    return status;

}


NTSTATUS WriteWMIEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {
    std::wstring Namespace, ESS, Consumer, PossibleCause;

    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = NULL;
    SYSTEMTIME systemTime;
    BYTE** propertyDataVector = NULL;
    PProcessInformation processInformation;
    GetSystemTime(&systemTime);

    //
    // Fetch initial event information size
    //
    status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (!pInfo) {
            OutputDebugString(L"Error allocating memory for event info\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
        status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
    }
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error fetching event info\n");
        return status;
    }

    //
    // Allocate memory for property data vector
    //
    propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
    if (!propertyDataVector) {
        OutputDebugString(L"Error allocating memory for propertyDataVector\n");
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto Exit;
    }

    status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error processing ETW event\n");
        goto Exit;
    }

    processInformation = GetProcessName(EventHeader->ProcessId);
    if (processInformation == nullptr) {
        OutputDebugString(L"DotNet ETW - Error getting process name\n");
        goto Exit;
    }

    Namespace = (WCHAR*)propertyDataVector[0];
    ESS = (WCHAR*)propertyDataVector[1];
    Consumer = (WCHAR*)propertyDataVector[2];
    PossibleCause = (WCHAR*)propertyDataVector[3];

    EventWriteWMIEventFilter(
        &systemTime,
        processInformation->processName.c_str(),
        processInformation->processId,
        processInformation->userName.c_str(),
        processInformation->authenticationId.LowPart,
        processInformation->integrityLevel.c_str(),
        processInformation->sessionId,
        Namespace.c_str(),
        ESS.c_str(),
        Consumer.c_str(),
        PossibleCause.c_str()
    );


Exit:
    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            if (propertyDataVector[i] != nullptr) {
                free(propertyDataVector[i]);
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}

wchar_t* GetCallStack(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER_EXTENDED_DATA_ITEM extendedData,
    _In_ HANDLE hProcess
) {
    const int MAX_SYM_NAME_LEN = 1024;
    std::wstring wtext;
    BOOL symInitialized = FALSE;

    const char* szSymSearchPath = "srv*http://msdl.microsoft.com/download/symbols";
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_CASE_INSENSITIVE | SYMOPT_ALLOW_ZERO_ADDRESS | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS);
    symInitialized = SymInitialize(hProcess, szSymSearchPath, TRUE);
    if (!symInitialized) {
        printf("[!] SymInitialize failed: %d\n", GetLastError());
        return nullptr;
    }

    if (EventRecord->ExtendedDataCount == 0) {
        SymCleanup(hProcess);
        return nullptr;
    }

    for (USHORT i = 0; i < EventRecord->ExtendedDataCount; i++) {
        if (extendedData[i].ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
            auto stacktrace = reinterpret_cast<PEVENT_EXTENDED_ITEM_STACK_TRACE64>(extendedData[i].DataPtr);
            int stack_length = extendedData[i].DataSize / sizeof(ULONG64);
            for (int j = 0; j < stack_length; j++) {
                DWORD64 dwDisplacement = 0;
                DWORD64 dwAddress = stacktrace->Address[j];
                char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME_LEN * sizeof(TCHAR)];
                PSYMBOL_INFOW pSymbol = (PSYMBOL_INFOW)buffer;
                pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
                pSymbol->MaxNameLen = MAX_SYM_NAME_LEN;

                if (SymFromAddrW(hProcess, dwAddress, &dwDisplacement, pSymbol)) {
                    wtext += pSymbol->Name;
                }
                else {
                    wtext += L"<Unknown>";
                }
                wtext += L" ";
            }
        }
    }

    SymCleanup(hProcess);

    if (!wtext.empty()) {
        wtext.pop_back();  // Remove trailing space
        size_t wtext_len = wtext.length() + 1;
        wchar_t* result = new wchar_t[wtext_len];
        wcscpy_s(result, wtext_len, wtext.c_str());
        return result;
    }

    return nullptr;
}

NTSTATUS WriteRpcEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader,
    _In_ INT32 EventType
) {
    PEVENT_HEADER_EXTENDED_DATA_ITEM extendedData = EventRecord->ExtendedData;
    wchar_t szInterfaceUUID[64] = { 0 };
    GUID interfaceUUID;
    UINT32 procNum, protocol, authenticationLevel, authenticationService, impersonationLevel;
    std::wstring networkAddress, endpoint, options, methodString, interfaceString;
    HANDLE hProcess = GetCurrentProcess();
    wchar_t* CallStack;
    int result;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = NULL;
    SYSTEMTIME systemTime;
    BYTE** propertyDataVector = NULL;
    PProcessInformation processInformation;
    GetSystemTime(&systemTime);

    //
    // Fetch initial event information size
    //
    status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (!pInfo) {
            OutputDebugString(L"Error allocating memory for event info\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
        status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
    }
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error fetching event info\n");
        return status;
    }

    //
    // Allocate memory for property data vector
    //
    propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
    if (!propertyDataVector) {
        OutputDebugString(L"Error allocating memory for propertyDataVector\n");
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto Exit;
    }

    status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error processing ETW event\n");
        goto Exit;
    }


    interfaceUUID = *(GUID*)propertyDataVector[0];
    procNum = *(UINT32*)propertyDataVector[1];
    protocol = *(UINT32*)propertyDataVector[2];
    networkAddress = (WCHAR*)propertyDataVector[3];
    endpoint = (WCHAR*)propertyDataVector[4];
    options = (WCHAR*)propertyDataVector[5];
    authenticationLevel = *(UINT32*)propertyDataVector[6];
    authenticationService = *(UINT32*)propertyDataVector[7];
    impersonationLevel = *(UINT32*)propertyDataVector[8];

    //
    // convert GUID to string
    //
    result = StringFromGUID2(interfaceUUID, szInterfaceUUID, 64);
    if (result == 0) {
        OutputDebugString(L"Error converting GUID to string\n");
        goto Exit;
    }


    //MS-SCMR {367ABB81-9844-35F1-AD32-98F038001003}
    if (wcscmp(szInterfaceUUID, L"{367ABB81-9844-35F1-AD32-98F038001003}") == 0) {
        interfaceString = L"MS-SCMR";
        switch (procNum)
        {
        case 12:
        {
            methodString = L"RCreateServiceW";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;

            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }
            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;

        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }
    //MS-DRSR {E3514235-4B06-11D1-AB04-00C04FC2DCD2}
    if (wcscmp(szInterfaceUUID, L"{E3514235-4B06-11D1-AB04-00C04FC2DCD2}") == 0) {
        interfaceString = L"MS-DRSR";
        switch (procNum) {
        case 3:
        {
            methodString = L"GetNCChanges";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;
            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }
            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;
        }
        default: {
            goto Exit;
        }
        }
        goto Exit;
    }
    //MS-RRP {338CD001-2244-31F1-AAAA-900038001003}
    if (wcscmp(szInterfaceUUID, L"{338CD001-2244-31F1-AAAA-900038001003}") == 0) {
        interfaceString = L"MS-RRP";
        switch (procNum) {
        case 6:
        {
            methodString = L"BaseRegCreateKey";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;
            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }
            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;

        }
        case 22:
        {
            methodString = L"BaseRegSetValue";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;
            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }
            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }

        }
        goto Exit;
    }
    //MS-SRVS {4B324FC8-1670-01D3-1278-5A47BF6EE188}
    if (wcscmp(szInterfaceUUID, L"{4B324FC8-1670-01D3-1278-5A47BF6EE188}") == 0) {
        interfaceString = L"MS-SRVS";
        switch (procNum) {
        case 12:
        {
            methodString = L"NetrSessionEnum";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;
            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }

            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }
    //MS-RPRN {12345678-1234-ABCD-EF00-0123456789AB}
    if (wcscmp(szInterfaceUUID, L"{12345678-1234-ABCD-EF00-0123456789AB}") == 0) {
        interfaceString = L"MS-RPRN";
        switch (procNum) {
        case 89:
        {
            methodString = L"RpcAddPrinterDriverEx";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;
            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }
            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }

    //MS-PAR 76F03F96-CDFD-44FC-A22C-64950A001209
    if (wcscmp(szInterfaceUUID, L"{76F03F96-CDFD-44FC-A22C-64950A001209}") == 0) {
        interfaceString = L"MS-PAR";
        switch (procNum) {
        case 39:
        {
            methodString = L"RpcAsyncAddPrinterDriver";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;
            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }
            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }
    // MS-EFSR {D9A0A0C0-150F-11D1-8C7A-00C04FC297EB} || {C681D488-D850-11D0-8C52-00C04FD90F7E}"
    if ((wcscmp(szInterfaceUUID, L"{C681D488-D850-11D0-8C52-00C04FD90F7E}") == 0) || (wcscmp(szInterfaceUUID, L"{DF1941C5-FE89-4E79-BF10-463657ACF44D}") == 0)) {
        interfaceString = L"MS-EFSR";
        switch (procNum) {
        case 0:
        {
            methodString = L"EfsRpcOpenFileRaw";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;
            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }
            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;
        }
        case 4:
        {
            methodString = L"EfsRpcEncryptFileSrv";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;
            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }
            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;
        }
        case 5:
        {
            methodString = L"EfsRpcDecryptFileSrv";
            processInformation = GetProcessName(EventHeader->ProcessId);
            if (processInformation == nullptr) {
                OutputDebugString(L"RPC ETW - Error getting process name\n");
                goto Exit;
            }
            CallStack = GetCallStack(EventRecord, extendedData, hProcess);
            switch (EventType)
            {
            case 0:
            {
                EventWriteRPCClient(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            case 1:
            {
                EventWriteRPCServer(
                    &systemTime,
                    processInformation->processName.c_str(),
                    processInformation->processId,
                    processInformation->userName.c_str(),
                    processInformation->authenticationId.LowPart,
                    processInformation->integrityLevel.c_str(),
                    processInformation->sessionId,
                    szInterfaceUUID,
                    procNum,
                    protocol,
                    networkAddress.c_str(),
                    endpoint.c_str(),
                    interfaceString.c_str(),
                    methodString.c_str(),
                    CallStack
                );
                break;
            }
            }
            if (CallStack != nullptr)
            {
                delete[] CallStack;
            }
            goto Exit;
        }
        default:
        {
            goto Exit;
        }
        }
        goto Exit;
    }

Exit:
    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            if (propertyDataVector[i] != nullptr) {
                free(propertyDataVector[i]);
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;

}

NTSTATUS WriteDpapiEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
) {

    UINT32 Flags, ProtectionFlags, ReturnValue, CallerProcessID, PlainTextDataSize;
    std::wstring OperationType, DataDescription;
    GUID MasterKeyGUID;
    UINT64 CallerProcessStartKey, CallerProcessCreationTime;
    NTSTATUS status = ERROR_SUCCESS;
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO pInfo = NULL;
    SYSTEMTIME systemTime;
    BYTE** propertyDataVector = NULL;
    PProcessInformation processInformation;
    GetSystemTime(&systemTime);

    //
    // Fetch initial event information size
    //
    status = TdhGetEventInformation(EventRecord, 0, NULL, NULL, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        if (!pInfo) {
            OutputDebugString(L"Error allocating memory for event info\n");
            status = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
        status = TdhGetEventInformation(EventRecord, 0, NULL, pInfo, &bufferSize);
    }
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error fetching event info\n");
        return status;
    }

    //
    // Allocate memory for property data vector
    //
    propertyDataVector = (BYTE**)malloc(sizeof(BYTE*) * pInfo->TopLevelPropertyCount);
    if (!propertyDataVector) {
        OutputDebugString(L"Error allocating memory for propertyDataVector\n");
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto Exit;
    }

    status = ProcessEtwEvent(EventRecord, pInfo, propertyDataVector);
    if (status != ERROR_SUCCESS) {
        OutputDebugString(L"Error processing ETW event\n");
        goto Exit;
    }


    OperationType = (WCHAR*)propertyDataVector[0];
    DataDescription = (WCHAR*)propertyDataVector[1];
    MasterKeyGUID = *(GUID*)propertyDataVector[2];
    Flags = *(UINT32*)propertyDataVector[3];
    ProtectionFlags = *(UINT32*)propertyDataVector[4];
    ReturnValue = *(UINT32*)propertyDataVector[5];
    CallerProcessStartKey = *(UINT64*)propertyDataVector[6];
    CallerProcessID = *(UINT32*)propertyDataVector[7];
    CallerProcessCreationTime = *(UINT64*)propertyDataVector[8];
    PlainTextDataSize = *(UINT32*)propertyDataVector[9];

    //
    //Seeing if OperationType == SPCryptUnprotect
    //
    if (OperationType == L"SPCryptUnprotect")
    {

        processInformation = GetProcessName(CallerProcessID);
        if (processInformation == nullptr) {
            OutputDebugString(L"DotNet ETW - Error getting process name\n");
            goto Exit;
        }

        EventWriteDPAPIUnprotect(
            &systemTime,
            processInformation->processName.c_str(),
            CallerProcessID,
            processInformation->userName.c_str(),
            processInformation->authenticationId.LowPart,
            processInformation->integrityLevel.c_str(),
            processInformation->sessionId,
            OperationType.c_str(),
            DataDescription.c_str(),
            Flags,
            ProtectionFlags
        );
    }

Exit:
    // Free each element in propertyDataVector and the vector itself
    if (propertyDataVector != nullptr) {
        for (int i = 0; i < pInfo->TopLevelPropertyCount; i++) {
            if (propertyDataVector[i] != nullptr) {
                free(propertyDataVector[i]);
            }
        }
        free(propertyDataVector);
    }

    if (pInfo != nullptr) {
        free(pInfo);
    }

    return status;
}