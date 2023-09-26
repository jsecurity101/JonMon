#pragma once
#include <evntcons.h>

struct ProcessData {
    ULONG ProcessId;
    ULONG ValueOption;
};
#define JonMon_DEVICE 0x8010

#define IOCTL_CHANGE_PROTECTION_LEVEL_PROCESS CTL_CODE(JonMon_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

void NTAPI ProcessEvent(
    _In_ PEVENT_RECORD EventRecord
);

int StopETWTrace();

int TraceEvent();

NTSTATUS WriteETWEvents(
    _In_ PEVENT_DATA_DESCRIPTOR eventData,
    _In_ EVENT_DESCRIPTOR eventDescriptor,
    _In_ int metaDataSize
);

BOOL WriteDotNetEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

BOOL WriteAMSIEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

BOOL WriteTaskSchedEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

BOOL WriteWMIEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);

BOOL WriteNetworkEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader, 
    _In_ wchar_t* Initiated
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

BOOL WriteRPCEvent(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader, 
    _In_ EVENT_DESCRIPTOR RPCEvent, 
    _In_ wchar_t* InterfaceString, 
    _In_ wchar_t* MethodString, 
    _In_ wchar_t* szInterfaceUUID, 
    _In_ wchar_t* CallStack
);

BOOL RpcEvent(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader, 
    _In_ EVENT_DESCRIPTOR RPCEvent
);

BOOL DPAPIEvents(
    _In_ PEVENT_RECORD EventRecord, 
    _In_ PEVENT_HEADER EventHeader
);