#ifndef _CALLBACK_
#define _CALLBACK_
#include "shared.h"

extern ULONG g_ServicePID;

extern PVOID ProcessRegistrationHandle;
extern PVOID ThreadRegistrationHandle;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegisterCallbacks(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PDEVICE_OBJECT DeviceObject
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID CreateProcessNotifyRoutineEx(
	_In_ PEPROCESS Process, 
	_In_ HANDLE ProcessId, 
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID PsCreateThreadNotifyRoutine(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID TerminateProcessNotifyRoutine(
	_In_ HANDLE ParentProcessId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
LoadImageWorkerThread(
	_In_ PVOID StartContext
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID 
LoadImageRoutine(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
);

_IRQL_requires_max_(PASSIVE_LEVEL)
void PostProcessHandleCallback(
	_In_ PVOID RegistrationContext,
	_In_ POB_POST_OPERATION_INFORMATION OperationInformation
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryCallback(
	_In_ PVOID CallbackContext,
	_In_ PVOID RegNotifyClass,
	_In_ PVOID RegObject
);

typedef struct _HANDLE_CREATION_CALLBACK_INFO {
	ULONGLONG SourceProcessStartKey;
	HANDLE SourceProcessId;
	HANDLE SourceThreadId;
	HANDLE TargetProcessId;
	PETHREAD SourceThread;
	ULONGLONG TargetProcessStartKey;
	ACCESS_MASK DesiredAccess;
	FILETIME FileTime;
	DWORD OperationType;
} HANDLE_CREATION_CALLBACK_INFO, * PHANDLE_CREATION_CALLBACK_INFO;

typedef struct _LOAD_IMAGE_CALLBACK_INFO {
	HANDLE SourceProcessId;
	HANDLE SourceThread;
	PETHREAD SourceEThread;
	FILETIME FileTime;
	UNICODE_STRING ModuleName;
	ULONG SystemModeImage;
} LOAD_IMAGE_CALLBACK_INFO, * PLOAD_IMAGE_CALLBACK_INFO;

typedef struct _PROCESS_CREATE_CALLBACK_INFO {
	PEPROCESS Process;
	HANDLE ProcessId;
	FILETIME FileTime;
	HANDLE ParentProcessId;
	CLIENT_ID CreatorId;
	UNICODE_STRING CommandLine;
} PROCESS_CREATE_CALLBACK_INFO, * PPROCESS_CREATE_CALLBACK_INFO;

typedef struct _THREAD_CREATE_CALLBACK_INFO {
	HANDLE SourceProcessId;
	HANDLE TargetProcessId;
	HANDLE TargetThreadId;
	FILETIME FileTime;
} THREAD_CREATE_CALLBACK_INFO, * PTHREAD_CREATE_CALLBACK_INFO;

typedef struct _PROCESS_TERMINATE_CALLBACK_INFO {
	FILETIME FileTime;
	HANDLE SourceProcessId;
	HANDLE TargetProcessId;
} PROCESS_TERMINATE_CALLBACK_INFO, * PPROCESS_TERMINATE_CALLBACK_INFO;

#endif // !_CALLBACK_
