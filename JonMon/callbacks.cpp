#include "callbacks.h"
#include "process.h"
#include "registry.h"
#include "minifilter.h"


PAGED_FILE();

#define MAX_PATH_LENGTH 100

PVOID ProcessRegistrationHandle = NULL;
PVOID ThreadRegistrationHandle = NULL;
LARGE_INTEGER Cookie;
ULONG g_ServicePID = 0;
PDRIVER_OBJECT g_DriverObject = NULL;


EventSchema g_EventSchema = { 
	FALSE, 
	FALSE, 
	FALSE, 
	FALSE, 
	FALSE, 
	FALSE, 
	FALSE, 
	FALSE,  
	FALSE, 
	0, 
	0 
};

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegisterCallbacks(
) {
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING Altitude;
	RtlInitUnicodeString(&Altitude, L"385202");

	//
	// Checks global g_EventSchema to see if ConfigSet is set to false, if it is will sleep and recheck
	//
	while (g_EventSchema.ConfigSet == FALSE) {
		LARGE_INTEGER interval;
		interval.QuadPart = -10000000; // 1 second
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	if(g_EventSchema.ProcessCreation == TRUE)
	{
		status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, FALSE);
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load PsSetCreateProcessNotifyRoutineEx : 0x%X\n", status);
			return status;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetCreateProcessNotifyRoutineEx Loaded\n");
	}

	if(g_EventSchema.ProcessTermination == TRUE)
	{
		status = PsSetCreateProcessNotifyRoutine(TerminateProcessNotifyRoutine, FALSE);
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load PsSetCreateProcessNotifyRoutine : 0x%X\n", status);
			return status;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetCreateProcessNotifyRoutine Loaded\n");
	}

	if(g_EventSchema.RemoteThreadCreation == TRUE)
	{
		status = PsSetCreateThreadNotifyRoutine(PsCreateThreadNotifyRoutine);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load PsSetCreateThreadNotifyRoutine : 0x%X\n", status);
			return status;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetCreateThreadNotifyRoutine Loaded\n");
	}

	if(g_EventSchema.ImageLoad == TRUE)
	{
		status = PsSetLoadImageNotifyRoutine(LoadImageRoutine);
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load PsSetLoadImageNotifyRoutine : 0x%X\n", status);
			return status;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetLoadImageNotifyRoutine Loaded\n");
	}
	
	if(g_EventSchema.ProcessHandleCreation == TRUE || g_EventSchema.ProcessHandleDuplication == TRUE)
	{
		// 
		//Setting up callback for PsProcessType
		//
		OB_CALLBACK_REGISTRATION CallbackRegistration;
		OB_OPERATION_REGISTRATION OperationRegistration;
		OperationRegistration.ObjectType = PsProcessType;

		if(g_EventSchema.ProcessHandleDuplication == TRUE && g_EventSchema.ProcessHandleCreation == TRUE)
		{
			OperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		}
		else if(g_EventSchema.ProcessHandleCreation == TRUE && g_EventSchema.ProcessHandleDuplication == FALSE)
		{
			OperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE;
		}
		else if(g_EventSchema.ProcessHandleDuplication == TRUE && g_EventSchema.ProcessHandleCreation == FALSE)
		{
			OperationRegistration.Operations = OB_OPERATION_HANDLE_DUPLICATE;
		}
		OperationRegistration.PreOperation = NULL;
		OperationRegistration.PostOperation = PostProcessHandleCallback;

		//
		// Setting members
		//
		CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		CallbackRegistration.OperationRegistrationCount = 1;
		CallbackRegistration.Altitude = Altitude;
		CallbackRegistration.RegistrationContext = NULL;
		CallbackRegistration.OperationRegistration = &OperationRegistration;

		status = ObRegisterCallbacks(&CallbackRegistration, &ProcessRegistrationHandle);
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load ObRegisterCallbacks : 0x%X\n", status);
			return status;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ObRegisterCallbacks Loaded\n");
	}

	if(g_EventSchema.File == TRUE)
	{
		status = FltCallbackStart(g_DriverObject);
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load FltCallbackStart : 0x%X\n", status);
			return status;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "FltCallbackStart Loaded\n");
	}
	
	if (g_EventSchema.Registry == TRUE)
	{
		status = CmRegisterCallbackEx(RegistryCallback, &Altitude, g_DriverObject, NULL, &Cookie, NULL);
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load CmRegisterCallbackEx : 0x%X\n", status);
			return status;
		}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CmRegisterCallbackEx Loaded\n");
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
	return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID 
LoadImageRoutine(
	_In_ PUNICODE_STRING FullImageName, 
	_In_ HANDLE ProcessId, 
	_In_ PIMAGE_INFO ImageInfo
) {
	FILETIME fileTime;
	KeQuerySystemTime(&fileTime);

	PAGED_CODE();

	ULONGLONG ProcessStartKey = PsGetProcessStartKey(PsGetCurrentProcess());

	TraceLoggingWrite(
		g_hJonMon,
		"ImageLoad",
		TraceLoggingInt32(4, "EventID"),
		TraceLoggingValue(ProcessId, "ProcessId"),
		TraceLoggingValue(ProcessStartKey, "ProcessStartKey"),
		TraceLoggingValue(PsGetCurrentThreadId(), "ThreadId"),
		TraceLoggingValue(ImageInfo->SystemModeImage, "SystemModeImage"),
		TraceLoggingWideString(FullImageName->Buffer, "ImagePath"),
		TraceLoggingFileTime(fileTime, "FileTime")
	);

}


BOOLEAN ContainsSubstring(PCWSTR keyPath, PCWSTR substring) {
	size_t keyPathLen = wcslen(keyPath);
	size_t substringLen = wcslen(substring);

	if (keyPathLen < substringLen) {
		return FALSE;
	}

	for (PCWSTR p = keyPath; *p != L'\0'; p++) {
		if (wcsncmp(p, substring, substringLen) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryCallback(
	_In_ PVOID CallbackContext, 
	_In_ PVOID RegNotifyClass, 
	_In_ PVOID RegObject
) {

	
	//
	//IRQL less == Passive, if not exit
	//
	if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
		return STATUS_UNSUCCESSFUL;
	}

	PCWSTR keyPath = NULL;
	FILETIME fileTime;
	REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)RegNotifyClass;
	NTSTATUS status = STATUS_SUCCESS;


	PAGED_CODE();
	UNREFERENCED_PARAMETER(CallbackContext);

	if (RegObject == NULL)
	{
		DbgPrint("Callback RegObject is NULL. \n");
		status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}

	KeQuerySystemTime(&fileTime);

	ULONGLONG sourceProcessId = HandleToULong(PsGetCurrentProcessId());
	ULONGLONG sourceThreadId = HandleToULong(PsGetCurrentThreadId());

	

	switch (notifyClass) {
	case RegNtPostCreateKeyEx:
	{
		PREG_POST_OPERATION_INFORMATION object = (PREG_POST_OPERATION_INFORMATION)RegObject;
		if (object->Status != STATUS_SUCCESS) {
				DbgPrint("[RegNtPostCreateKeyEx] - Status is not success. Status 0x%x\n", object->Status);
				goto Exit;
		}
		PREG_CREATE_KEY_INFORMATION_V1 info = (PREG_CREATE_KEY_INFORMATION_V1)object->PreInformation;
		if (*info->Disposition != REG_CREATED_NEW_KEY ) {
			DbgPrint("[RegNtPostCreateKeyEx] - Disposition is not REG_CREATED_NEW_KEY. Disposition 0x%x\n", *info->Disposition);
			goto Exit;
		}
		status = GetRegistryKeyPath(object->Object, REGISTRY_TAG, &keyPath);
		if (status != STATUS_SUCCESS || keyPath == NULL) {
			DbgPrint("[RegNtPostCreateKeyEx] - GetRegistryKeyPath failed. Status 0x%x\n", status);
			goto Exit;
		}
			
		TraceLoggingWrite(
			g_hJonMon,
			"RegCreateKey",
			TraceLoggingInt32(9, "EventID"),
			TraceLoggingValue(sourceThreadId, "SourceThreadId"),
			TraceLoggingValue(sourceProcessId, "SourceProcessId"),
			TraceLoggingValue(PsGetProcessStartKey(PsGetCurrentProcess()), "SourceProcessStartKey"),
			TraceLoggingWideString(keyPath, "KeyPath"),
			TraceLoggingValue(info->DesiredAccess, "DesiredAccess"),
			TraceLoggingFileTime(fileTime, "FileTime")
		);

		break;
	}
	case RegNtPostSaveKey:
	{
		PREG_POST_OPERATION_INFORMATION object = (PREG_POST_OPERATION_INFORMATION)RegObject;
		if (object->Status == STATUS_SUCCESS) {
			status = GetRegistryKeyPath(object->Object, REGISTRY_TAG, &keyPath);
			if (keyPath == NULL) {
				goto Exit;
			}

			TraceLoggingWrite(
				g_hJonMon,
				"RegSaveKey",
				TraceLoggingInt32(6, "EventID"),
				TraceLoggingValue(sourceThreadId, "SourceThreadId"),
				TraceLoggingValue(sourceProcessId, "SourceProcessId"),
				TraceLoggingValue(PsGetProcessStartKey(PsGetCurrentProcess()), "SourceProcessStartKey"),
				TraceLoggingWideString(keyPath, "KeyPath"),
				TraceLoggingFileTime(fileTime, "FileTime")
			);
			
		}
		break;
	}
	case RegNtPreDeleteKey:
	{
		PREG_DELETE_KEY_INFORMATION object = (PREG_DELETE_KEY_INFORMATION)RegObject;
		if (object->Object == NULL)
		{
			goto Exit;
		}
		status = GetRegistryKeyPath(object->Object, REGISTRY_TAG, &keyPath);
		if (keyPath == NULL) {
			goto Exit;
		}
		
		TraceLoggingWrite(
			g_hJonMon,
			"RegDeleteKey",
			TraceLoggingInt32(7, "EventID"),
			TraceLoggingValue(sourceThreadId, "SourceThreadId"),
			TraceLoggingValue(sourceProcessId, "SourceProcessId"),
			TraceLoggingValue(PsGetProcessStartKey(PsGetCurrentProcess()), "SourceProcessStartKey"),
			TraceLoggingWideString(keyPath, "KeyPath"),
			TraceLoggingFileTime(fileTime, "FileTime")
		);

		break;
	}
	case RegNtPostSetValueKey:
	{


		UNICODE_STRING valueData;

		PREG_POST_OPERATION_INFORMATION postObject = (PREG_POST_OPERATION_INFORMATION)RegObject;
		if (postObject->Status != STATUS_SUCCESS) {
			goto Exit;
		}
		PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)postObject->PreInformation;
		if (info->ValueName == NULL || info->ValueName->Length == 0) {
			goto Exit;
		}

		status = GetRegistryKeyPath(info->Object, REGISTRY_TAG, &keyPath);
		if (status != STATUS_SUCCESS || keyPath == NULL) {
			DbgPrint("[RegNtPostSetValueKey] - GetRegistryKeyPath failed. Status 0x%x", status);
			goto Exit;
		}

		if (info->DataSize <= 0) {
			goto Exit;
		}
		if(info->Data == NULL)
		{
			goto Exit;
		}

		//
		// Reducing noise
		//
		if (ContainsSubstring(keyPath, L"DeliveryOptimization\\Usage")) {
			goto Exit;
		}
		if (ContainsSubstring(keyPath, L"\\DeliveryOptimization\\Config")) {
			goto Exit;
		}
		if (ContainsSubstring(keyPath, L"\\Microsoft\\Input\\TypingInsights")) {
			goto Exit;
		}
		if (ContainsSubstring(keyPath, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\W32Time")) {
			goto Exit;
		}
		if (ContainsSubstring(keyPath, L"\\REGISTRY\\A\\")) {
			goto Exit;
		}

		//
		// Fixing valueName buffer
		//
		UNICODE_STRING valueName;
		valueName.Length = info->ValueName->Length;
		valueName.MaximumLength = info->ValueName->Length + sizeof(UNICODE_NULL);
		valueName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, valueName.MaximumLength, SYSTEM_THREAD_TAG);	// Use valueName.Length here.
		if (valueName.Buffer == NULL || valueName.Length == 0) {
			goto Exit;
		}
		RtlZeroMemory(valueName.Buffer, valueName.MaximumLength);
		RtlCopyMemory(valueName.Buffer, info->ValueName->Buffer, info->ValueName->Length);

		//
		// adding null terminator
		//
		valueName.Buffer[valueName.Length / sizeof(WCHAR)] = UNICODE_NULL;



		//
		// Creating a UNICODE_STRING to hold the data information
		//
		valueData.Length = (USHORT)info->DataSize;
		valueData.MaximumLength = valueData.Length + sizeof(WCHAR);  // Account for null terminator
		valueData.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, valueData.MaximumLength, SYSTEM_THREAD_TAG);
		if (valueData.Buffer == NULL || valueData.MaximumLength == 0) {
			goto Exit;
		}
		RtlZeroMemory(valueData.Buffer, valueData.MaximumLength);

		//
		// To do: Update REG_MULTI_SZ and REG_BINARY
		//
		switch (info->Type)
		{
			case REG_SZ:
			{
				RtlCopyMemory(valueData.Buffer, info->Data, valueData.Length);
				valueData.Buffer[valueData.Length / sizeof(WCHAR)] = UNICODE_NULL;  // Set null terminator
				break;
			}
			case REG_EXPAND_SZ:
			{
				RtlCopyMemory(valueData.Buffer, info->Data, valueData.Length);
				valueData.Buffer[valueData.Length / sizeof(WCHAR)] = UNICODE_NULL;  // Set null terminator
				break;
			}
			case REG_MULTI_SZ:
			{
				RtlCopyMemory(valueData.Buffer, info->Data, valueData.Length);

				// Ensure the data is properly double-null terminated
				if (valueData.Length >= sizeof(WCHAR) && valueData.Buffer[(valueData.Length / sizeof(WCHAR)) - 1] != UNICODE_NULL)
				{
					// Add an additional null terminator if the last character isn't already a null terminator
					valueData.Buffer[valueData.Length / sizeof(WCHAR)] = UNICODE_NULL; // First null terminator
					valueData.Buffer[(valueData.Length / sizeof(WCHAR)) + 1] = UNICODE_NULL; // Second null terminator
				}
				else 
				{
					// If the data already ends with a null, just add another
					valueData.Buffer[valueData.Length / sizeof(WCHAR)] = UNICODE_NULL;
				}
				break;
			}
			case REG_DWORD:
			{
				RtlStringCchPrintfW(valueData.Buffer, valueData.MaximumLength / sizeof(WCHAR), L"%d", *(DWORD*)info->Data);
				break;
			}
			case REG_QWORD:
			{
				RtlStringCchPrintfW(valueData.Buffer, valueData.MaximumLength / sizeof(WCHAR), L"%lld", *(ULONGLONG*)info->Data);
				break;
			}
			case REG_BINARY:
			{
				RtlStringCchPrintfW(valueData.Buffer, valueData.MaximumLength / sizeof(WCHAR), L"%d", *(DWORD*)info->Data);
				break;
			}
			default:
			{
				break;
			}
		}


		//
		// check each field below to see if it is null lol
		//
		if (keyPath == NULL)
		{
			DbgPrint("keyPath is NULL\n");
		}
		if (valueName.Buffer == NULL)
		{
			DbgPrint("valueName.Buffer is NULL\n");
		}
		if (valueData.Buffer == NULL)
		{
			DbgPrint("valueData.Buffer is NULL\n");
		}
		if(info->Type == NULL)
		{
			DbgPrint("info->Type is NULL\n");
		}
		if(info->DataSize == NULL)
		{
			DbgPrint("info->DataSize is NULL\n");
		}


		TraceLoggingWrite(
			g_hJonMon,
			"RegSetValueKey",
			TraceLoggingInt32(8, "EventID"),
			TraceLoggingValue(sourceThreadId, "SourceThreadId"),
			TraceLoggingValue(sourceProcessId, "SourceProcessId"),
			TraceLoggingValue(PsGetProcessStartKey(PsGetCurrentProcess()), "SourceProcessStartKey"),
			TraceLoggingWideString(keyPath, "KeyPath"),
			TraceLoggingWideString(valueName.Buffer, "ValueName"),
			TraceLoggingValue(valueData.Buffer, "Data"),
			TraceLoggingValue(info->Type, "Type"),
			TraceLoggingValue(info->DataSize, "DataSize"),
			TraceLoggingFileTime(fileTime, "FileTime")
		);


		if(valueName.Buffer != NULL)
		{
			ExFreePoolWithTag(valueName.Buffer, SYSTEM_THREAD_TAG);
		}
		if(valueData.Buffer != NULL)
		{
			ExFreePoolWithTag(valueData.Buffer, SYSTEM_THREAD_TAG);
		}
		break;
	}
	default:
	{
		break;
	}
	}

Exit:

	if (keyPath != NULL) {
		ExFreePoolWithTag((PVOID)keyPath, REGISTRY_TAG);
	}
	return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void PsCreateThreadNotifyRoutine(
	_In_ HANDLE ProcessId, 
	_In_ HANDLE ThreadId, 
	_In_ BOOLEAN Create
) {
	NTSTATUS status;
	PEPROCESS sourceProcess;
	PEPROCESS targetProcess;
	FILETIME filetime;

	KeQuerySystemTime(&filetime);

	PAGED_CODE();

	//
	// Check if the thread is being created or deleted
	//
	if (Create != TRUE) {
		goto Exit;
	}
	HANDLE CurrentPID = PsGetCurrentProcessId();

	if (CurrentPID == ProcessId) {
		goto Exit;
	}

	if (CurrentPID == (HANDLE)0x4) {
		goto Exit;
	}

	if (ProcessId == (HANDLE)0x4) {
		goto Exit;
	}

	HANDLE sourceThreadId = PsGetCurrentThreadId();

	status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Failed to get target process, status:  %d", status);
		goto Exit;
	}

	status = PsLookupProcessByProcessId(CurrentPID, &sourceProcess);

	if (status != STATUS_SUCCESS) {
		DbgPrint("Failed to get source process, status:  %d", status);
		goto Exit;
	}

	ULONGLONG sourceProcStartKey = PsGetProcessStartKey(sourceProcess);
	ULONGLONG targetProcStartKey = PsGetProcessStartKey(targetProcess);

	TraceLoggingWrite(
		g_hJonMon,
		"RemoteThreadCreation",
		TraceLoggingInt32(3, "EventID"),
		TraceLoggingValue(sourceThreadId, "SourceThreadId"),
		TraceLoggingValue(CurrentPID, "SourceProcessId"),
		TraceLoggingValue(sourceProcStartKey, "SourceProcessStartKey"),
		TraceLoggingValue(ThreadId, "NewThreadId"),
		TraceLoggingValue(ProcessId, "TargetProcessId"),
		TraceLoggingValue(targetProcStartKey, "TargetProcessStartKey"),
		TraceLoggingFileTime(filetime, "FileTime")
	);



Exit:
	return;
	
}


_IRQL_requires_max_(PASSIVE_LEVEL)
void CreateProcessNotifyRoutineEx(
	_In_ PEPROCESS Process, 
	_In_ HANDLE ProcessId, 
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	FILETIME fileTime;
	UNICODE_STRING commandLine{ 0 };

	PAGED_CODE();	

	if (CreateInfo == NULL)
	{
		goto Exit;

	}
	KeQuerySystemTime(&fileTime);

	ULONGLONG ProcessStartKey = PsGetProcessStartKey(Process);
	ULONGLONG parentProcessStartKey = PsGetProcessStartKey(PsGetCurrentProcess());

	//
	//Checking to see if CommandLine is NULL and if it isn't, creating a buffer
	//
	if (CreateInfo->CommandLine != NULL) {
		//
		//create buffer
		//
		commandLine.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, CreateInfo->CommandLine->Length + sizeof(UNICODE_NULL), SYSTEM_THREAD_TAG);
		if (commandLine.Buffer == NULL)
		{
			goto Exit;
		}

		//
		//Zero out the buffer
		//
		RtlZeroMemory(commandLine.Buffer, CreateInfo->CommandLine->Length + sizeof(UNICODE_NULL));


		//
		//Copy the CommandLine into the buffer
		//
		RtlCopyMemory(commandLine.Buffer, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);

		//
		//Null terminate the buffer
		//
		commandLine.Buffer[CreateInfo->CommandLine->Length / sizeof(UNICODE_NULL)] = UNICODE_NULL;
	}
	else {
		commandLine.Buffer = L"NULL";
		commandLine.Length = sizeof(L"NULL");
		commandLine.MaximumLength = sizeof(L"NULL") + sizeof(UNICODE_NULL);
	}

	//
	// TraceLogging Event
	//
	TraceLoggingWrite(
		g_hJonMon, 
		"ProcessCreation",
		TraceLoggingInt32(1, "EventID"),
		TraceLoggingValue(ProcessId, "ProcessId"),
		TraceLoggingValue(ProcessStartKey, "ProcessStartKey"),
		TraceLoggingValue(CreateInfo->ParentProcessId, "ParentProcessId"),
		TraceLoggingValue(parentProcessStartKey, "ParentProcessStartKey"),
		TraceLoggingValue(CreateInfo->CreatingThreadId.UniqueProcess, "CreatorProcessId"),
		TraceLoggingValue(CreateInfo->CreatingThreadId.UniqueThread, "CreatorThreadId"),
		TraceLoggingWideString(commandLine.Buffer, "CommandLine"),
		TraceLoggingFileTime(fileTime, "FileTime")
	);


Exit:
	if (commandLine.Buffer != NULL) {
		ExFreePoolWithTag(commandLine.Buffer, SYSTEM_THREAD_TAG);
	}
}


_IRQL_requires_max_(PASSIVE_LEVEL)
void PostProcessHandleCallback(
	_In_ PVOID RegistrationContext, 
	_In_ POB_POST_OPERATION_INFORMATION OperationInformation
) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	FILETIME filetime;
	DWORD OperationType;
	ACCESS_MASK DesiredAccess;

	PAGED_CODE();
	KeQuerySystemTime(&filetime);

	PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;

	HANDLE TargetProcessId = PsGetProcessId(targetProcess);
	HANDLE SourceProcessId = PsGetCurrentProcessId();
	DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.GrantedAccess;


	if ((HANDLE)g_ServicePID == SourceProcessId) {
		goto Exit;
	}


	if (DesiredAccess == 0x0) {
		goto Exit;
	}

	if (SourceProcessId == TargetProcessId) {
		goto Exit;
	}

	if (SourceProcessId == (HANDLE)0x4 || TargetProcessId == (HANDLE)0x4) {
		goto Exit;
	}
	
	switch (OperationInformation->Operation)
	{
		case OB_OPERATION_HANDLE_CREATE:
		{
			OperationType = 1;
			break;
		}
		case OB_OPERATION_HANDLE_DUPLICATE:
		{
			if ((DesiredAccess & 0x40) != 0x40) {
				goto Exit;
			}
			DesiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.GrantedAccess;
			OperationType = 2;
			break;
		}
	}

	TraceLoggingWrite(
		g_hJonMon,
		"ProcessHandle",
		TraceLoggingInt32(5, "EventID"),
		TraceLoggingValue(PsGetCurrentThreadId(), "SourceThreadId"),
		TraceLoggingValue(SourceProcessId, "SourceProcessId"),
		TraceLoggingValue(PsGetProcessStartKey(PsGetCurrentProcess()), "SourceProcessStartKey"),
		TraceLoggingValue(TargetProcessId, "TargetProcessId"),
		TraceLoggingValue(PsGetProcessStartKey(targetProcess), "TargetProcessStartKey"),
		TraceLoggingValue(OperationType, "OperationType"),
		TraceLoggingValue(DesiredAccess, "DesiredAccess"),
		TraceLoggingFileTime(filetime, "FileTime")
	);

Exit:
	return;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void TerminateProcessNotifyRoutine(
	_In_ HANDLE ParentProcessId, 
	_In_ HANDLE ProcessId, 
	_In_ BOOLEAN Create
)
{
	FILETIME fileTime;

	PAGED_CODE();

	if (!Create)
	{
		KeQuerySystemTime(&fileTime);
		ULONGLONG sourceProcessStartKey = PsGetProcessStartKey(PsGetCurrentProcess());
		ULONGLONG targetProcessStartKey = PsGetProcessStartKey(PsGetCurrentProcess());

		TraceLoggingWrite(
			g_hJonMon,
			"ProcessTermination",
			TraceLoggingInt32(2, "EventID"),
			TraceLoggingValue(ProcessId, "ProcessId"),
			TraceLoggingValue(targetProcessStartKey, "ProcessStartKey"),
			TraceLoggingValue(ParentProcessId, "ParentProcessId"),
			TraceLoggingValue(sourceProcessStartKey, "ParentProcessStartKey"),
			TraceLoggingFileTime(fileTime, "FileTime")
		);

		goto Exit;
	}
Exit:
	return;
}