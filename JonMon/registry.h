#ifndef _REGISTRY_
#define _REGISTRY_
#include <ntifs.h>

//
// Structure to hold registry callback info
//
typedef struct _REG_SET_VALUE_CALLBACK_INFO
{
	PEPROCESS SourceProcess;
	HANDLE SourceProcessId;
	HANDLE SourceThreadId;
	PETHREAD SourceThread;
	ULONG Type;
	PCWSTR KeyPath;
	PVOID Data;
	ULONG DataSize;
	UNICODE_STRING ValueName;
} REG_SET_VALUE_CALLBACK_INFO, * PREG_SET_VALUE_CALLBACK_INFO;

typedef struct _REG_CREATE_KEY_CALLBACK_INFO
{
	HANDLE SourceProcessId;
	ULONGLONG ProcStartKey;
	PETHREAD SourceThread;
	HANDLE SourceThreadId;
	ACCESS_MASK DesiredAccess;
	UNICODE_STRING KeyPath;
} REG_CREATE_KEY_CALLBACK_INFO, * PREG_CREATE_KEY_CALLBACK_INFO;

typedef struct _REG_DELETE_KEY_CALLBACK_INFO
{
	PEPROCESS SourceProcess;
	HANDLE SourceProcessId;
	HANDLE SourceThreadId;
	PCWSTR KeyPath;
} REG_DELETE_KEY_CALLBACK_INFO, * PREG_DELETE_KEY_CALLBACK_INFO;

NTSTATUS 
GetRegistryKeyPath(
	_In_ PVOID object, 
	_In_ ULONG tag, 
	_In_ PCWSTR* keyPath
);

VOID 
SendSetValueRegistryInfo(
	_In_ PVOID StartContext
);

VOID 
DeleteKey(
	_In_ PVOID context, 
	_In_ PREG_DELETE_KEY_INFORMATION info
);

VOID 
CreateKey(
	_In_ PVOID StartContext
);

VOID 
SaveKey(
	_In_ PVOID context, 
	_In_ PREG_SAVE_KEY_INFORMATION info
);

#endif // !_REGISTRY_