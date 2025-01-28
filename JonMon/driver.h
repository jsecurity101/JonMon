#ifndef _DRIVER_
#define _DRIVER_
#include "shared.h"

/*
* Global variable to store the registry path
*/

#define JonMon_DEVICE 0x8010

#define IOCTL_CHANGE_PROTECTION_LEVEL_PROCESS CTL_CODE(JonMon_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EVENT_CONFIGURATION CTL_CODE(JonMon_DEVICE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

UNICODE_STRING g_RegPath;

typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	KPRIORITY      BasePriority;
	ULONG          ContextSwitchCount;
	LONG           State;
	LONG           WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {
	ULONG            NextEntryDelta;
	ULONG            ThreadCount;
	ULONG            Reserved1[6];
	LARGE_INTEGER    CreateTime;
	LARGE_INTEGER    UserTime;
	LARGE_INTEGER    KernelTime;
	UNICODE_STRING   ProcessName;
	KPRIORITY        BasePriority;
	SIZE_T           ProcessId;
	SIZE_T           InheritedFromProcessId;
	ULONG            HandleCount;
	ULONG            Reserved2[2];
	VM_COUNTERS      VmCounters;
	IO_COUNTERS      IoCounters;
	SYSTEM_THREADS   Threads[1];
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;


typedef struct _PS_PROTECTION {
	UCHAR Type : 3;
	UCHAR Audit : 1;
	UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROCESS_SIGNATURE_PROTECTION {
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;
} PROCESS_SIGNATURE_PROTECTION, * PPROCESS_SIGNATURE_PROTECTION;

typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
	);

ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
/*
* Driver Function Protoypes
*/
NTSTATUS JonMonCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject, 
	_In_ PIRP Irp
);

NTSTATUS CompleteRequest(
	PIRP Irp, 
	NTSTATUS status = STATUS_SUCCESS, 
	ULONG_PTR info = 0
);


NTSTATUS JonMonDeviceControl(
	_In_ PDEVICE_OBJECT, 
	_In_ PIRP Irp
);


VOID JonMonUnload(
	_In_ PDRIVER_OBJECT DriverObject
);

VOID AlterPPL(
	_In_ ULONG PID, 
	_In_ ULONG value
);
VOID ChangePPL();


#endif // !_DRIVER_