#pragma once
#include <evntcons.h>
#include <iostream>

#include <evntrace.h>
#include <tdh.h>

#include "../JonMonProvider/jonmon.h"
#include "config.h"

static GUID JonMonGuid = { 0xd8909c24, 0x5be9, 0x4502, { 0x98, 0xca, 0xab, 0x7b, 0xdc, 0x24, 0x89, 0x9d } };
static GUID JonMonDebugGuid = { 0xc5d8e634, 0x9614, 0x45ac, { 0x93, 0x0c, 0xda, 0x88, 0xcd, 0x77, 0xbb, 0x39 } };

struct ProcessData {
    ULONG ProcessId;
    ULONG ValueOption;
};

NTSTATUS ProcessEtwEvent(
	_In_ PEVENT_RECORD EventRecord,
	_In_ PTRACE_EVENT_INFO PropertyInfo,
	_In_ BYTE** EventData
);

void NTAPI ProcessEvent(
    _In_ PEVENT_RECORD EventRecord
);

DWORD StopETWTrace();

DWORD TraceEvent(
	_In_ LPCWSTR Name,
	_In_ GUID TraceGuid,
	_In_ EventSchema_Full* EventSchemaStruct
);

NTSTATUS WriteJonMonTraceLoggingEvents(
    _In_ PEVENT_RECORD EventRecord,
    _In_ PEVENT_HEADER EventHeader
);

NTSTATUS WriteDotNetEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

BOOL WriteAMSIEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

NTSTATUS WriteWMIEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

BOOL WriteNetworkEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

NTSTATUS WriteThreatIntelEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

#pragma warning(disable: 4996)
wchar_t* GetCallStack(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER_EXTENDED_DATA_ITEM extendedData, 
    _In_ HANDLE hProcess
);

NTSTATUS WriteRpcEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader, 
    _In_ INT32 EventType
);

NTSTATUS WriteDpapiEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

//
// Event ID 100
//
typedef struct _TraceLoggingProviderRegistered {
	INT32 EventId;
	BOOL IsRegistered;
} TraceLoggingProviderRegistered, * PTraceLoggingProviderRegistered;

//
// Event ID 101
// 
typedef struct _EventSchemaConfiguration {
	INT32 EventId;
    BOOL ProcessCreation;
    BOOL ProcessTermination;
    BOOL RegistryEvents;
    BOOL ProcessHandleCreation;
    BOOL ProcessHandleDuplication;
    BOOL RemoteThreadCreation;
    BOOL ImageLoad;
    BOOL ThreadImpersonationEvents_KM;
    BOOL FileEvents;
} EventSchemaConfiguration, * PEventSchemaConfiguration;

//
// Event ID 102
//
typedef struct _DebugLog {
	INT32 EventId;
	BOOL ProcessProtection;
} DebugLog, * PDebugLog;


//
//Event ID 1 - Process Creation
//
typedef struct _ProcessCreationEvent {
    INT32 EventId;
    INT64 ProcessId;
    UINT64 ProcessStartKey;
    INT64 ParentProcessId;
    UINT64 ParentProcessStartKey;
    INT64 CreatorProcessId;
    INT64 CreatorThreadId;
    WCHAR* CommandLine;
    FILETIME EventTime;
} ProcessCreationEvent, * PProcessCreationEvent;

//
// Event ID 2 - Process Termination
//
typedef struct _ProcessTerminationEvent {
	INT32 EventId;
	INT64 ProcessId;
	UINT64 ProcessStartKey;
    INT64 ParentProcessId;
    UINT64 ParentProcessStartKey;
	FILETIME EventTime;
} ProcessTerminationEvent, * PProcessTerminationEvent;

//
// Event ID 3 - Remote Thread Creation
//
typedef struct _RemoteThreadCreationEvent {
	INT32 EventId;
    INT64 SourceThreadId;
	INT64 SourceProcessId;
    UINT64 SourceProcessStartKey;
    INT64 NewThreadId;
	INT64 TargetProcessId;
	UINT64 TargetProcessStartKey;
	FILETIME EventTime;
} RemoteThreadCreationEvent, * PRemoteThreadCreationEvent;

//
// Event ID 4 - Load Image
//
typedef struct _LoadImageEvent {
	INT32 EventId;
	INT64 ProcessId;
	UINT64 ProcessStartKey;
    INT64 ThreadId;
    ULONG SystemModeImage;
    WCHAR* ImageName;
	FILETIME EventTime;
} LoadImageEvent, * PLoadImageEvent;

//
// Event ID 5 - ProcessHandle (OpenProcess/DuplicateHandle)
//
typedef struct _ProcessHandleEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	INT64 TargetProcessId;
	UINT64 TargetProcessStartKey;
	INT32 OperationType;
	INT32 DesiredAccess;
	FILETIME EventTime;
} ProcessHandleEvent, * PProcessHandleEvent;

//
// Event ID 6 - RegistrySaveKey
//
typedef struct _RegistrySaveKeyEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* KeyPath;
	FILETIME EventTime;
} RegistrySaveKeyEvent, * PRegistrySaveKeyEvent;

//
// Event ID 7 - RegistryDeleteKey
//
typedef struct _RegistryDeleteKeyEvent {
    INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* KeyPath;
	FILETIME EventTime;
} RegistryDeleteKeyEvent, * PRegistryDeleteKeyEvent;

//
// Event ID 8 - RegistrySetValue
//
typedef struct _RegistrySetValueKeyEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* KeyPath;
	WCHAR* ValueName;
	WCHAR* Data;
	ULONG Type;
	ULONG DataSize;
	FILETIME EventTime;
} RegistrySetValueKeyEvent, * PRegistrySetValueKeyEvent;

//
// Event ID 9 - RegistryCreateKey
//
typedef struct _RegistryCreateKeyEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* KeyPath;
	INT32 DesiredAccess;
	FILETIME EventTime;
} RegistryCreateKeyEvent, * PRegistryCreateKeyEvent;

//
// Event ID 10 - File Creation
//
typedef struct _FileCreationEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* FileName;
	FILETIME EventTime;
} FileCreationEvent, * PFileCreationEvent;

//
// Event ID 11 - NamedPipeCreation
//
typedef struct _NamedPipeCreateEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* FileName;
	ULONG RequestedRights;
	ULONG GrantedRights;
	FILETIME EventTime;
} NamedPipeCreateEvent, * PNamedPipeCreateEvent;

//
// Event ID 12 - NamedPipeConnection
//
typedef struct _NamedPipeConnectionEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* FileName;
	ULONG RequestedRights;
	FILETIME EventTime;
} NamedPipeConnectionEvent, * PNamedPipeConnectionEvent;

//
// Event ID 13 - MailslotCreation
//
typedef struct _MailslotCreateEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* FileName;
	ULONG RequestedRights;
	FILETIME EventTime;
} MailslotCreateEvent, * PMailslotCreateEvent;

//
// Event ID 14 - MailslotConnection
//
typedef struct _MailslotConnectionEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* FileName;
	ULONG RequestedRights;
	FILETIME EventTime;
} MailslotConnectionEvent, * PMailslotConnectionEvent;

//
// Event ID 15 - RemoteFileConnection (Named Pipes/Mailslots)
//
typedef struct _RemoteFileConnectionEvent {
	INT32 EventId;
	INT64 SourceThreadId;
	INT64 SourceProcessId;
	UINT64 SourceProcessStartKey;
	WCHAR* FileName;
	FILETIME EventTime;
} RemoteFileConnectionEvent, * PRemoteFileConnectionEvent;


//
// Event ID 16 - ThreadImpersonation
//
typedef struct _ThreadImpersonationEvent {
	INT32 EventId;
	UINT32 ThreadId;
	UINT32 ProcessId;
	UINT32 threadIntegrityLevel;
	SYSTEMTIME EventTime;
	WCHAR* ImpersonatedUser;
} ThreadImpersonationEvent, * PThreadImpersonationEvent;
