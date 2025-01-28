#ifndef _SHARED_
#define _SHARED_
#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>
#include <wdm.h>
#include <Ntstrsafe.h>
#include <fltKernel.h>
#include <time.h>
#include <TraceLoggingProvider.h> 
#include <minwindef.h>
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)


TRACELOGGING_DECLARE_PROVIDER(g_hJonMon);

/*
TraceLogging Event Schema:
---- Security Events ----
EID 1 - Process Creation
EID 2 - Process Termination
EID 3 - Remote Thread Creation
EID 4 - Load Image
EID 5 - ProcessHandle (OpenProcess/DuplicateHandle)
EID 6 - RegistrySaveKey
EID 7 - RegistryDeleteKey
EID 8 - RegistrySetValue
EID 9 - RegistryCreateKey
EID 10 - FileOperation (CreateFile)
EID 11 - NamedPipeCreation 
EID 12 - NamedPipeConnection
EID 13 - MailslotCreation
EID 14 - MailslotConnection
EID 15 - RemoteFileConnection (Named Pipes/Mailslots)

---- Debug/Informational Events ----
EID 100 - TraceLogging Provider Registered (True or False)
EID 101 - Event Schema Configuration
EID 102 - Protection Level Changed 
*/

//
// https://github.com/winsiderss/systeminformer/blob/0e3d514e23cf4813ba5895c74b6d596c8966e1b3/KSystemInformer/include/kph.h#L31
//
#define PAGED_PASSIVE()\
    PAGED_CODE()\
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)

//
// https://github.com/winsiderss/systeminformer/blob/0e3d514e23cf4813ba5895c74b6d596c8966e1b3/KSystemInformer/include/kph.h#L31
//
#define PAGED_FILE() \
    __pragma(bss_seg("PAGEBBS"))\
    __pragma(code_seg("PAGE"))\
    __pragma(data_seg("PAGEDATA"))\
    __pragma(const_seg("PAGERO"))

/*
* Creating tags to be used with in different scenerios of memory allocation
*/
#define DRIVER_TAG 'monj'
#define REGISTRY_TAG 'regj'
#define PROCESS_TAG 'prcj'
#define THREAD_TAG 'thrj'
#define TOKEN_TAG 'tknj'
#define FILE_TAG 'flj'
#define CALBACK_TAG 'clkj'
#define SYSTEM_THREAD_TAG 'rhsj'

#define MAX_ALLOC 260

extern LARGE_INTEGER Cookie;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessInformation = 5,
} SYSTEM_INFORMATION_CLASS;

typedef struct _LIST_ENTRY* PLIST_ENTRY;
typedef struct _THREAD_LIST_ENTRY* PTHREAD_LIST_ENTRY;

typedef struct _THREAD_LIST_ENTRY {
	PLIST_ENTRY PrevThread;
	PLIST_ENTRY NextThread;
	PETHREAD Thread;
} THREAD_LIST_ENTRY, * PTHREAD_LIST_ENTRY;

#endif // !_SHARED_