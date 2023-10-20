#include "callbacks.h"
#include "process.h"
#include "thread.h"
#include "token.h"
#include "registry.h"
#include "minifilter.h"

PAGED_FILE();

#define MAX_PATH_LENGTH 100

PVOID ProcessRegistrationHandle = NULL;
PVOID ThreadRegistrationHandle = NULL;
LARGE_INTEGER Cookie;
ULONG g_ServicePID = 0;

//
// Registering callbacks for log collection
//
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegisterCallbacks(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PDEVICE_OBJECT DeviceObject
) {
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(DriverObject);
	PAGED_CODE();
	NTSTATUS status = STATUS_SUCCESS;

	status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load PsSetCreateProcessNotifyRoutineEx : 0x%X\n", status);
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetCreateProcessNotifyRoutineEx Loaded\n");
	
	status = PsSetCreateProcessNotifyRoutine(TerminateProcessNotifyRoutine, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load PsSetCreateProcessNotifyRoutine : 0x%X\n", status);
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetCreateProcessNotifyRoutine Loaded\n");

	status = PsSetCreateThreadNotifyRoutine(PsCreateThreadNotifyRoutine);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load PsSetCreateThreadNotifyRoutine : 0x%X\n", status);
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetCreateThreadNotifyRoutine Loaded\n");

	status = PsSetLoadImageNotifyRoutine(LoadImageRoutine);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load PsSetLoadImageNotifyRoutine : 0x%X\n", status);
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetLoadImageNotifyRoutine Loaded\n");

	UNICODE_STRING Altitude;
	RtlInitUnicodeString(&Altitude, L"385202");

	// 
	//Setting up callback for PsProcessType
	//
	OB_CALLBACK_REGISTRATION CallbackRegistration;
	OB_OPERATION_REGISTRATION OperationRegistration;
	OperationRegistration.ObjectType = PsProcessType;
	OperationRegistration.Operations = OB_OPERATION_HANDLE_DUPLICATE | OB_OPERATION_HANDLE_CREATE;
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

	status = FltCallbackStart(DriverObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load FltCallbackStart : 0x%X\n", status);
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "FltCallbackStart Loaded\n");

	status = CmRegisterCallbackEx(RegistryCallback, &Altitude, DriverObject, NULL, &Cookie, NULL);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to load CmRegisterCallbackEx : 0x%X\n", status);
		return status;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CmRegisterCallbackEx Loaded\n");

	return status;
}

// [DONE]
// LoadImage callback worker thread. This function will perform the appropriate processing and then terminate.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID LoadImageWorkerThread(
	_In_ PVOID StartContext
) {
	PLOAD_IMAGE_CALLBACK_INFO callbackInfo = NULL;
	UNICODE_STRING imagePath{ 0 };
	UNICODE_STRING sourceFullUserName{};
	NTSTATUS status;
	ULONG systemModeImage;

	PAGED_CODE();

	callbackInfo = (PLOAD_IMAGE_CALLBACK_INFO)StartContext;

	FILETIME filetime = callbackInfo->FileTime;
	HANDLE sourcePID = callbackInfo->SourceProcessId;
	ULONGLONG uSourcePID = HandleToULong(sourcePID);
	ULONGLONG sourceThreadID = HandleToULong(callbackInfo->SourceThread);

	systemModeImage = callbackInfo->SystemModeImage;

	PEPROCESS sourceProcess;

	if (systemModeImage == 1)
	{
		EventWriteDriverLoad(NULL, &filetime, callbackInfo->ModuleName.Buffer);
		goto Exit;
	}

	status = PsLookupProcessByProcessId(sourcePID, &sourceProcess);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	ULONGLONG sourceProcessStartKey = PsGetProcessStartKey(sourceProcess);
	imagePath.Length = 0;
	imagePath.MaximumLength = MAX_ALLOC;
	imagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, CALBACK_TAG);
	status = GetProcessImageName(sourcePID, &imagePath);
	if (!NT_SUCCESS(status) || imagePath.Buffer == NULL) {
		goto Exit;
	}

	sourceFullUserName.Length = 0;
	sourceFullUserName.MaximumLength = MAX_ALLOC;
	sourceFullUserName.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, sourceFullUserName.MaximumLength, CALBACK_TAG);
	if (sourceFullUserName.Buffer == NULL) {
		goto Exit;
	}

	DWORD SourceAuthenticationId = 0;
	status = GetProcessUserName(&sourceFullUserName, sourcePID, &SourceAuthenticationId);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	
	EventWriteImageLoaded(NULL, &filetime, imagePath.Buffer, uSourcePID, sourceThreadID, sourceProcessStartKey, callbackInfo->ModuleName.Buffer, sourceFullUserName.Buffer, SourceAuthenticationId);


Exit:
	if (sourceFullUserName.Buffer != NULL) {
		ExFreePoolWithTag(sourceFullUserName.Buffer, CALBACK_TAG);
	}
	if (imagePath.Buffer != NULL) {
		ExFreePoolWithTag(imagePath.Buffer, CALBACK_TAG);
	}
	if (callbackInfo->ModuleName.Buffer != NULL)
	{
		ExFreePoolWithTag(callbackInfo->ModuleName.Buffer, CALBACK_TAG);
	}
	if (callbackInfo != NULL) {
		ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

// [DONE]
// LoadImage callback. Routine will capture when an image is loaded into a process and will create a worker thread to perform the appropriate processing.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID 
LoadImageRoutine(
	_In_ PUNICODE_STRING FullImageName, 
	_In_ HANDLE ProcessId, 
	_In_ PIMAGE_INFO ImageInfo
) {
	NTSTATUS status;
	FILETIME fileTime;
	HANDLE hLoadImageThread = NULL;
	UNICODE_STRING imagePath{ 0 };
	KeQuerySystemTime(&fileTime);
	PAGED_CODE();

	auto callbackInfo = (PLOAD_IMAGE_CALLBACK_INFO)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(LOAD_IMAGE_CALLBACK_INFO), SYSTEM_THREAD_TAG);
	if (callbackInfo == NULL) {
		goto Exit;
	}
	
	imagePath.Length = FullImageName->Length + sizeof(UNICODE_NULL);
	imagePath.MaximumLength = FullImageName->Length + sizeof(UNICODE_NULL);
	imagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, imagePath.MaximumLength, CALBACK_TAG);
	if (imagePath.Buffer == NULL) {
		goto Exit;
	}
	//
	// Copy the image path into the callback info structure.
	//
	RtlCopyUnicodeString(&imagePath, FullImageName);

	//
	//null terminate the string
	//
	imagePath.Buffer[imagePath.Length / sizeof(UNICODE_NULL)] = UNICODE_NULL;


	//
	//setting the callback info structure
	//
	callbackInfo->ModuleName = imagePath;


	callbackInfo->FileTime = fileTime;
	callbackInfo->SourceProcessId = ProcessId;
	callbackInfo->SourceThread = NtCurrentThread();
	callbackInfo->SourceEThread = PsGetCurrentThread();
	callbackInfo->SystemModeImage = ImageInfo->SystemModeImage;


	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	status = PsCreateSystemThread(&hLoadImageThread, THREAD_ALL_ACCESS, &objectAttributes, NULL, NULL, (PKSTART_ROUTINE)LoadImageWorkerThread, callbackInfo);
	if (!NT_SUCCESS(status)) {
		DbgPrint("PsCreateSystemThread failed: %x\n", status);
		ExFreePoolWithTag(imagePath.Buffer, CALBACK_TAG);
		ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
		goto Exit;
	}

Exit: 
	if(hLoadImageThread != NULL)
	{
		ZwClose(hLoadImageThread);
	}

	return;
}

// [DONE]
// Registry callback to capture registry actions and create a worker thread to perform the appropriate processing.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS RegistryCallback(
	_In_ PVOID CallbackContext, 
	_In_ PVOID RegNotifyClass, 
	_In_ PVOID RegObject
) {
	NTSTATUS status = STATUS_SUCCESS;
	PCWSTR keyPath = NULL;
	HANDLE registryThreadHandle = NULL;
	REG_NOTIFY_CLASS notifyClass;
	notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)RegNotifyClass;


	PAGED_CODE();
	UNREFERENCED_PARAMETER(CallbackContext);

	if (RegObject == NULL)
	{
		DbgPrint("Callback RegObject is NULL. \n");
		status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}
	switch (notifyClass) {
	case RegNtPostCreateKeyEx:
	{
		PREG_POST_OPERATION_INFORMATION postObject = (PREG_POST_OPERATION_INFORMATION)RegObject;
		if (postObject->Status == STATUS_SUCCESS) {
			PREG_CREATE_KEY_INFORMATION_V1 info = (PREG_CREATE_KEY_INFORMATION_V1)postObject->PreInformation;
			if (*info->Disposition == REG_CREATED_NEW_KEY) {
				if (info->CompleteName->Buffer != NULL)
				{
					PCUNICODE_STRING registryPath = NULL;
					status = CmCallbackGetKeyObjectIDEx(&Cookie, info->RootObject, NULL, &registryPath, 0);
					if (!NT_SUCCESS(status)) {
						DbgPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", status);
						goto Exit;
					}

					UNICODE_STRING regPath;
					regPath.Length = registryPath->Length + info->RemainingName->Length + sizeof(L"\\") + sizeof(UNICODE_NULL);
					regPath.MaximumLength = registryPath->Length + info->RemainingName->Length + sizeof(L"\\") + sizeof(UNICODE_NULL);
					regPath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, regPath.Length, REGISTRY_TAG);

					RtlCopyUnicodeString(&regPath, registryPath);
					RtlAppendUnicodeToString(&regPath, L"\\");
					RtlAppendUnicodeStringToString(&regPath, info->RemainingName);

					//
					//adding null terminator
					//
					regPath.Buffer[regPath.Length / sizeof(UNICODE_NULL)] = UNICODE_NULL;

					auto callbackInfo = (PREG_CREATE_KEY_CALLBACK_INFO)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(REG_CREATE_KEY_CALLBACK_INFO), SYSTEM_THREAD_TAG);
					if (callbackInfo == NULL) {
						goto Exit;
					}
					callbackInfo->DesiredAccess = info->DesiredAccess;
					callbackInfo->ProcStartKey = PsGetProcessStartKey(PsGetCurrentProcess());
					callbackInfo->SourceProcessId = PsGetCurrentProcessId();
					callbackInfo->KeyPath = regPath;
					callbackInfo->SourceThread = PsGetCurrentThread();
					callbackInfo->SourceThreadId = PsGetCurrentThreadId();

					CmCallbackReleaseKeyObjectIDEx(registryPath);

					OBJECT_ATTRIBUTES objectAttributes;
					InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
					status = PsCreateSystemThread(&registryThreadHandle, THREAD_ALL_ACCESS, &objectAttributes, NULL, NULL, (PKSTART_ROUTINE)CreateKey, callbackInfo);
					if (!NT_SUCCESS(status))
					{
						DbgPrint("PsCreateSystemThread failed: %x\n", status);
						ExFreePoolWithTag(regPath.Buffer, REGISTRY_TAG);
						ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
						goto Exit;
					}
					goto Exit;
				}
			}
			goto Exit;
		}
		goto Exit;
		break;
	}
	case RegNtPostSaveKey:
	{
		PREG_POST_OPERATION_INFORMATION postObject = (PREG_POST_OPERATION_INFORMATION)RegObject;
		if (postObject->Status == STATUS_SUCCESS) {
			SaveKey(CallbackContext, (PREG_SAVE_KEY_INFORMATION)postObject->PreInformation);
		}
		//goto Exit;
		break;
	}
	case RegNtPreDeleteKey:
	{
		PREG_DELETE_KEY_INFORMATION DeleteObject = (PREG_DELETE_KEY_INFORMATION)RegObject;
		if (DeleteObject->Object != NULL)
		{
			DeleteKey(CallbackContext, (PREG_DELETE_KEY_INFORMATION)RegObject);
		}
		//goto Exit;
		break;
	}
	case RegNtPostSetValueKey:
	{
		PREG_POST_OPERATION_INFORMATION postObject = (PREG_POST_OPERATION_INFORMATION)RegObject;
		if (postObject->Status != STATUS_SUCCESS) {
			goto Exit;
		}
		PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)postObject->PreInformation;


		//
		// creating a copy of the value name, otherwise it will be cleared by the callback
		//
		if (info->ValueName == NULL || info->ValueName->Length == 0) {
			goto Exit;
		}

		status = GetRegistryKeyPath(info->Object, SYSTEM_THREAD_TAG, &keyPath);
		if (status != STATUS_SUCCESS || keyPath == NULL) {
			DbgPrint("[RegNtPostSetValueKey] - GetRegistryKeyPath failed. Status 0x%x", status);
			goto Exit;
		}

		//
		// Allocating memory for the callback info structure
		//
		auto callbackInfo = (PREG_SET_VALUE_CALLBACK_INFO)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(REG_SET_VALUE_CALLBACK_INFO), SYSTEM_THREAD_TAG);
		if (callbackInfo == NULL) {
			goto Exit;
		}
		if (info->DataSize <= 0) {
			ExFreePoolWithTag((PVOID)keyPath, SYSTEM_THREAD_TAG);
			ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
			goto Exit;
		}
		PVOID Data = ExAllocatePool2(POOL_FLAG_PAGED, info->DataSize, SYSTEM_THREAD_TAG);
		if (Data == NULL) {
			ExFreePoolWithTag((PVOID)keyPath, SYSTEM_THREAD_TAG);
			ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
			goto Exit;
		}

		RtlCopyMemory(Data, info->Data, info->DataSize);

		UNICODE_STRING valueName;
		valueName.Length = info->ValueName->Length + sizeof(UNICODE_NULL);	// Compensate for NULL terminator.
		valueName.MaximumLength = info->ValueName->Length + sizeof(UNICODE_NULL);
		valueName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, valueName.Length, SYSTEM_THREAD_TAG);	// Use valueName.Length here.
		if (valueName.Buffer == NULL || valueName.Length == 0) {
			ExFreePoolWithTag((PVOID)keyPath, SYSTEM_THREAD_TAG);
			ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
			goto Exit;
		}

		//
		// Copy and NULL terminate the string. The Length member of the UNICODE_STRING doesn't compensate for the NULL terminator.
		//
		RtlCopyUnicodeString(&valueName, info->ValueName);
		valueName.Buffer[valueName.Length / sizeof(UNICODE_NULL)] = UNICODE_NULL;

		callbackInfo->Data = Data;
		callbackInfo->KeyPath = keyPath;
		callbackInfo->Type = info->Type;
		callbackInfo->ValueName = valueName;
		callbackInfo->SourceProcessId = PsGetCurrentProcessId();
		callbackInfo->SourceThreadId = PsGetCurrentThreadId();
		callbackInfo->SourceProcess = PsGetCurrentProcess();
		callbackInfo->SourceThread = PsGetCurrentThread();
		callbackInfo->DataSize = info->DataSize;
		OBJECT_ATTRIBUTES objectAttributes;
		InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

		status = PsCreateSystemThread(&registryThreadHandle, GENERIC_ALL, &objectAttributes, NULL, NULL, (PKSTART_ROUTINE)SendSetValueRegistryInfo, callbackInfo);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[RegNtPostSetValueKey] - PsCreateSystemThread failed. Status 0x%x", status);
			ExFreePoolWithTag((PVOID)keyPath, SYSTEM_THREAD_TAG);
			ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
			ExFreePoolWithTag(valueName.Buffer, SYSTEM_THREAD_TAG);
			//goto Exit;
		}
		//goto Exit;
		break;
	}
	default:
	{
		break;
	}
	}
Exit:

	if (registryThreadHandle != NULL) {
		ZwClose(registryThreadHandle);
	}
	return status;
}

// [DONE]
// Thread Creation routine that captures remote thread creation
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void PsCreateThreadNotifyRoutine(
	_In_ HANDLE ProcessId, 
	_In_ HANDLE ThreadId, 
	_In_ BOOLEAN Create
) {
	NTSTATUS status;
	PEPROCESS sourceProcess;
	PEPROCESS targetProcess;
	UNICODE_STRING sourceImage = { 0 };
	UNICODE_STRING sourceUserName = { 0 };
	UNICODE_STRING targetImage = { 0 };
	UNICODE_STRING targetUserName = { 0 };
	UNICODE_STRING sIntegrityLevel = { 0 };
	UNICODE_STRING tIntegrityLevel = { 0 };
	DWORD sourceAuthenticationId, targetAuthenticationId = 0;
	HANDLE tToken = NULL;
	HANDLE sToken = NULL;


	PAGED_CODE();
	//Checking for thread creation
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
		return;
	}
	status = PsLookupProcessByProcessId(CurrentPID, &sourceProcess);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Failed to get source process, status:  %d", status);
		return;
	}
	ULONGLONG sourceProcStartKey = PsGetProcessStartKey(sourceProcess);
	ULONGLONG targetProcStartKey = PsGetProcessStartKey(targetProcess);
	//Source Process Information
				
	sourceImage.Length = 0;
	sourceImage.MaximumLength = MAX_ALLOC;
	sourceImage.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, CALBACK_TAG);

	status = GetProcessImageName(CurrentPID, &sourceImage);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Error getting source image name: %d", status);
		sourceImage.Buffer = L"Unknown";
	}

	
	sourceUserName.Length = 0;
	sourceUserName.MaximumLength = MAX_ALLOC;
	sourceUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, CALBACK_TAG);
	status = GetProcessUserName(&sourceUserName, CurrentPID, &sourceAuthenticationId);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Error getting source user name: %d", status);
		goto Exit;
	}

	if (sourceUserName.Length == 0)
	{
		goto Exit;
	}

	//Create unicode string that holds "SYSTEM"
	UNICODE_STRING SystemName;
	RtlInitUnicodeString(&SystemName, L"NT AUTHORITY\\SYSTEM");
	if (RtlCompareUnicodeString(&sourceUserName, &SystemName, TRUE) == 0)
	{
		goto Exit;
	}
					
	status = GetProcessToken(CurrentPID, &sToken);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Error getting source token: %d", status);
		sToken = NULL;
	}
	
	status = GetTokenIntegrityLevel(sToken, &sIntegrityLevel);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Error getting source integrity level: %d", status);
		sIntegrityLevel.Buffer = L"Unknown";
	}

	//Target Process Information
	targetImage.Length = 0;
	targetImage.MaximumLength = MAX_ALLOC;
	targetImage.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, CALBACK_TAG);
	status = GetProcessImageName(ProcessId, &targetImage);
	if (status != STATUS_SUCCESS) {
		goto Exit;
	}

	targetUserName.Length = 0;
	targetUserName.MaximumLength = MAX_ALLOC;
	targetUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, CALBACK_TAG);
	status = GetProcessUserName(&targetUserName, ProcessId, &targetAuthenticationId);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Error getting target user name: %d", status);
		goto Exit;
	}
					
	status = GetProcessToken(ProcessId, &tToken);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Error getting target token: %d", status);
		tToken = NULL;
	}

	status = GetTokenIntegrityLevel(tToken, &tIntegrityLevel);
	if (status != STATUS_SUCCESS) {
		DbgPrint("Error getting target integrity level: %d", status);
		tIntegrityLevel.Buffer = L"Unknown";
	}

	FILETIME filetime;
	KeQuerySystemTime(&filetime);

	EventWriteRemoteThreadCreation(NULL, &filetime, sourceImage.Buffer, reinterpret_cast<ULONGLONG>(CurrentPID), reinterpret_cast<ULONGLONG>(sourceThreadId), sourceProcStartKey, sourceUserName.Buffer, sourceAuthenticationId, sIntegrityLevel.Buffer, targetImage.Buffer, reinterpret_cast<ULONGLONG>(ProcessId), targetProcStartKey, reinterpret_cast<ULONGLONG>(ThreadId), targetUserName.Buffer, targetAuthenticationId, tIntegrityLevel.Buffer);

Exit:
	if (sourceUserName.Buffer != NULL && sourceUserName.Length != 0) {
		ExFreePoolWithTag(sourceUserName.Buffer, CALBACK_TAG);
	}
	if (targetUserName.Buffer != NULL && targetUserName.Length != 0) {
		ExFreePoolWithTag(targetUserName.Buffer, CALBACK_TAG);
	}
	if (sourceImage.Buffer != NULL && sourceImage.Length != 0) {
		ExFreePoolWithTag(sourceImage.Buffer, CALBACK_TAG);
	}
	if (targetImage.Buffer != NULL && targetImage.Length != 0) {
		ExFreePoolWithTag(targetImage.Buffer, CALBACK_TAG);
	}
	if (sToken != NULL) {
		ZwClose(sToken);
	}
	if (tToken != NULL) {
		ZwClose(tToken);
	}
	
}

// [DONE]
// Create Process Worker Thread
//
VOID CreateProcessWorkerThread(
	_In_ PVOID StartContext
) {
	PPROCESS_CREATE_CALLBACK_INFO callbackInfo = NULL;
	UNICODE_STRING processImagePath{};
	UNICODE_STRING parentImagePath{};
	UNICODE_STRING parentUserName{};
	UNICODE_STRING creatorUserName{};
	UNICODE_STRING creatorImagePath{};
	UNICODE_STRING childUserName{};
	DWORD parentAuthenticationId = 0;
	DWORD childAuthenticationId = 0;
	DWORD creatorAuthenticationId = 0;
	NTSTATUS status;

	PAGED_CODE();

	callbackInfo = (PPROCESS_CREATE_CALLBACK_INFO)StartContext;

	HANDLE sourcePID = callbackInfo->ParentProcessId;
	HANDLE targetPID = callbackInfo->ProcessId;
	PEPROCESS targetProcess = callbackInfo->Process;
	FILETIME fileTime = callbackInfo->FileTime;
	CLIENT_ID creatorId = callbackInfo->CreatorId;

	ULONGLONG sourceThreadId = HandleToULong(creatorId.UniqueThread);

	ULONGLONG procStartKey = PsGetProcessStartKey(targetProcess);
	ULONGLONG procStartTime = PsGetProcessCreateTimeQuadPart(targetProcess);

	parentImagePath.Length = 0;
	parentImagePath.MaximumLength = MAX_ALLOC;
	parentImagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, SYSTEM_THREAD_TAG);
	status = GetProcessImageName(sourcePID, &parentImagePath);
	if (status != STATUS_SUCCESS) {
		goto Exit;
	}

	parentUserName.Length = 0;
	parentUserName.MaximumLength = MAX_ALLOC;
	parentUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, SYSTEM_THREAD_TAG);
	status = GetProcessUserName(&parentUserName, sourcePID, &parentAuthenticationId);
	if (status != STATUS_SUCCESS) {
		goto Exit;
	}

	processImagePath.Length = 0;
	processImagePath.MaximumLength = MAX_ALLOC;
	processImagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, SYSTEM_THREAD_TAG);
	status = GetProcessImageName(targetPID, &processImagePath);
	if (status != STATUS_SUCCESS) {
		goto Exit;
	}

	childUserName.Length = 0;
	childUserName.MaximumLength = MAX_ALLOC;
	childUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, SYSTEM_THREAD_TAG);
	status = GetProcessUserName(&childUserName, targetPID, &childAuthenticationId);
	if (status != STATUS_SUCCESS) {
		goto Exit;
	}

	ULONGLONG uParentPID = HandleToULong(sourcePID);
	ULONGLONG uTargetPID = HandleToULong(targetPID); 
	ULONGLONG uCreatorPID = HandleToULong(creatorId.UniqueProcess);
	
	EventWriteProcessCreation(NULL, &fileTime, processImagePath.Buffer, callbackInfo->CommandLine.Buffer, uTargetPID, procStartKey, procStartTime, childUserName.Buffer, childAuthenticationId, uParentPID, sourceThreadId, parentImagePath.Buffer, uCreatorPID, parentUserName.Buffer, parentAuthenticationId);


	if (uParentPID != uCreatorPID) {
		creatorUserName.Length = 0;
		creatorUserName.MaximumLength = MAX_ALLOC;
		creatorUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, SYSTEM_THREAD_TAG);
		status = GetProcessUserName(&creatorUserName, creatorId.UniqueProcess, &creatorAuthenticationId);
		if (status != STATUS_SUCCESS) {
			goto Exit;
		}

		creatorImagePath.Length = 0;
		creatorImagePath.MaximumLength = MAX_ALLOC;
		creatorImagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, SYSTEM_THREAD_TAG);
		status = GetProcessImageName(creatorId.UniqueProcess, &creatorImagePath);
		if (status != STATUS_SUCCESS) {
			goto Exit;
		}
		EventWriteProcessReparenting(NULL, &fileTime, processImagePath.Buffer, callbackInfo->CommandLine.Buffer, uParentPID, sourceThreadId, uTargetPID, procStartKey, procStartTime, parentImagePath.Buffer, uCreatorPID, creatorImagePath.Buffer, creatorUserName.Buffer, parentUserName.Buffer, childUserName.Buffer, parentAuthenticationId, childAuthenticationId, creatorAuthenticationId);
		goto Exit;
	}


Exit:
	if (processImagePath.Buffer != NULL) {
		ExFreePoolWithTag(processImagePath.Buffer, SYSTEM_THREAD_TAG);
	}
	if (parentImagePath.Buffer != NULL) {
		ExFreePoolWithTag(parentImagePath.Buffer, SYSTEM_THREAD_TAG);
	}
	if (parentUserName.Buffer != NULL) {
		ExFreePoolWithTag(parentUserName.Buffer, SYSTEM_THREAD_TAG);
	}
	if (childUserName.Buffer != NULL) {
		ExFreePoolWithTag(childUserName.Buffer, SYSTEM_THREAD_TAG);
	}
	if (creatorUserName.Buffer != NULL) {
		ExFreePoolWithTag(creatorUserName.Buffer, SYSTEM_THREAD_TAG);
	}
	if (creatorImagePath.Buffer != NULL) {
		ExFreePoolWithTag(creatorImagePath.Buffer, SYSTEM_THREAD_TAG);
	}
	if (callbackInfo->CommandLine.Buffer != NULL) {
		ExFreePoolWithTag(callbackInfo->CommandLine.Buffer, SYSTEM_THREAD_TAG);
	}
	if (callbackInfo != NULL) {
		ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

//
// Callback routine to capture process creation events
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void CreateProcessNotifyRoutineEx(
	_In_ PEPROCESS Process, 
	_In_ HANDLE ProcessId, 
	_In_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	NTSTATUS status;
	FILETIME fileTime;
	HANDLE hCreateProcessThread = NULL;
	UNICODE_STRING commandLine{ 0 };

	PAGED_CODE();	

	if (CreateInfo == NULL)
	{
		goto Exit;

	}
	KeQuerySystemTime(&fileTime);
	auto callbackInfo = (PPROCESS_CREATE_CALLBACK_INFO)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(PROCESS_CREATE_CALLBACK_INFO), SYSTEM_THREAD_TAG);
	if (callbackInfo == NULL) {
		return;
	}

	callbackInfo->ParentProcessId = CreateInfo->ParentProcessId;
	callbackInfo->FileTime = fileTime;
	callbackInfo->CreatorId = CreateInfo->CreatingThreadId;
	callbackInfo->ProcessId = ProcessId;
	callbackInfo->Process = Process;
	//callbackInfo->CommandLine = CreateInfo->CommandLine->Buffer;

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
			ExFreePoolWithTag(commandLine.Buffer, SYSTEM_THREAD_TAG);
			ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
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

	callbackInfo->CommandLine = commandLine;


	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	
	status = PsCreateSystemThread(&hCreateProcessThread, THREAD_ALL_ACCESS, &objectAttributes, NULL, NULL, (PKSTART_ROUTINE)CreateProcessWorkerThread, callbackInfo);
	if (!NT_SUCCESS(status)) {
		DbgPrint("PsCreateSystemThread failed: %x\n", status);
		ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
		return;
	}

Exit:
	if (hCreateProcessThread != NULL)
	{
		ZwClose(hCreateProcessThread);
	}
}


// [DONE]
// Post Handle (Open/Duplication) Worker Thread
//
VOID PostHandleWorkerThread(PVOID StartContext) {
	PHANDLE_CREATION_CALLBACK_INFO callbackInfo = NULL;
	UNICODE_STRING TargetImagePath{}, RequestorImagePath{}, SourceFullUserName{};
	NTSTATUS status;
	
	PAGED_CODE();

	callbackInfo = (PHANDLE_CREATION_CALLBACK_INFO)StartContext;
	if (callbackInfo == NULL)
	{
		goto Exit;
	}

	FILETIME filetime = callbackInfo->FileTime;
	HANDLE targetPID = callbackInfo->TargetProcessId;
	HANDLE sourcePID = callbackInfo->SourceProcessId;
	ULONGLONG UTargetPID = HandleToULong(targetPID);
	ULONGLONG USourcePID = HandleToULong(sourcePID);
	ULONGLONG sourceThreadId = HandleToULong(callbackInfo->SourceThreadId);
	ULONGLONG sourceProcessStartKey = callbackInfo->SourceProcessStartKey;
	ULONGLONG targetProcessStartKey = callbackInfo->TargetProcessStartKey;
	DWORD OperationType = callbackInfo->OperationType;
	ACCESS_MASK DesiredAccess = callbackInfo->DesiredAccess;	
	

	RequestorImagePath.Length = 0;
	RequestorImagePath.MaximumLength = MAX_ALLOC;
	RequestorImagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, SYSTEM_THREAD_TAG);
	status = GetProcessImageName(sourcePID, &RequestorImagePath);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	SourceFullUserName.Length = 0;
	SourceFullUserName.MaximumLength = MAX_ALLOC;
	SourceFullUserName.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, SourceFullUserName.MaximumLength, SYSTEM_THREAD_TAG);
	if (SourceFullUserName.Buffer == NULL) {
		goto Exit;
	}

	DWORD SourceAuthenticationId = 0;
	status = GetProcessUserName(&SourceFullUserName, sourcePID, &SourceAuthenticationId);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	TargetImagePath.Length = 0;
	TargetImagePath.MaximumLength = MAX_ALLOC;
	TargetImagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, SYSTEM_THREAD_TAG);
	status = GetProcessImageName(targetPID, &TargetImagePath);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}
	if (OperationType == 1) {
		EventWriteProcessAccess(NULL, &filetime, DesiredAccess, UTargetPID, targetProcessStartKey, TargetImagePath.Buffer, USourcePID, sourceThreadId, sourceProcessStartKey, RequestorImagePath.Buffer, SourceFullUserName.Buffer, SourceAuthenticationId);
		

		//
		// Grabbing impersonation data
		//
		HANDLE hToken = NULL;
		status = GetProcessToken(sourcePID, &hToken);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}
		DWORD SessionId = GetSessionIdFromToken(hToken);
		if (SessionId != 0) {
			status = ThreadImpersonationEvent(hToken, callbackInfo->SourceThread, L"OpenProcess", RequestorImagePath.Buffer, USourcePID, sourceProcessStartKey, UTargetPID, targetProcessStartKey);
		}
		if (hToken != NULL) {
			ZwClose(hToken);
		}
		//
		// End of querying for impersonation
		//
		goto Exit;
	}
	if (OperationType == 2) {
		EventWriteProcessAccessDuplicated(NULL, &filetime, DesiredAccess, UTargetPID, targetProcessStartKey, TargetImagePath.Buffer, USourcePID, sourceThreadId, sourceProcessStartKey, RequestorImagePath.Buffer, SourceFullUserName.Buffer, SourceAuthenticationId);
		goto Exit;
	}

Exit:
	if (TargetImagePath.Buffer != NULL) {
		ExFreePoolWithTag(TargetImagePath.Buffer, SYSTEM_THREAD_TAG);
	}
	if (SourceFullUserName.Buffer != NULL) {
		ExFreePoolWithTag(SourceFullUserName.Buffer, SYSTEM_THREAD_TAG);
	}
	if (RequestorImagePath.Buffer != NULL) {
		ExFreePoolWithTag(RequestorImagePath.Buffer, SYSTEM_THREAD_TAG);
	}
	ExFreePoolWithTag(StartContext, SYSTEM_THREAD_TAG);


	PsTerminateSystemThread(STATUS_SUCCESS);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void PostProcessHandleCallback(
	_In_ PVOID RegistrationContext, 
	_In_ POB_POST_OPERATION_INFORMATION OperationInformation
) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	HANDLE hPostHandleWorkerThread = NULL;
	NTSTATUS status;
	FILETIME filetime;

	PAGED_CODE();

	PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;

	HANDLE TargetProcessId = PsGetProcessId(targetProcess);
	HANDLE SourceProcessId = PsGetCurrentProcessId();

	if ((HANDLE)g_ServicePID == SourceProcessId) {
		goto Exit;
	}
	
	ACCESS_MASK CreatedGrantedAccess = OperationInformation->Parameters->CreateHandleInformation.GrantedAccess;

	KeQuerySystemTime(&filetime);

	if (CreatedGrantedAccess == 0x0) {
		goto Exit;
	}

	if (SourceProcessId == TargetProcessId) {
		goto Exit;
	}

	if (SourceProcessId == (HANDLE)0x4 || TargetProcessId == (HANDLE)0x4) {
		goto Exit;
	}

	PHANDLE_CREATION_CALLBACK_INFO callbackInfo = NULL;
	callbackInfo = (PHANDLE_CREATION_CALLBACK_INFO)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(HANDLE_CREATION_CALLBACK_INFO), SYSTEM_THREAD_TAG);
	if (callbackInfo == NULL) {
		DbgPrint("ExAllocatePool2 failed\n");
		goto Exit;
	}

	callbackInfo->SourceProcessId = SourceProcessId;
	callbackInfo->SourceThreadId = PsGetCurrentThreadId();
	callbackInfo->TargetProcessId = TargetProcessId;
	callbackInfo->SourceProcessStartKey = PsGetProcessStartKey(PsGetCurrentProcess());
	callbackInfo->TargetProcessStartKey = PsGetProcessStartKey(targetProcess);
	callbackInfo->FileTime = filetime;
	callbackInfo->SourceThread = PsGetCurrentThread();
	
	switch (OperationInformation->Operation)
	{
		case OB_OPERATION_HANDLE_CREATE:
		{
			callbackInfo->DesiredAccess = CreatedGrantedAccess;
			callbackInfo->OperationType = 1;
			break;
		}
		case OB_OPERATION_HANDLE_DUPLICATE:
		{
			if ((CreatedGrantedAccess & 0x40) != 0x40) {
				if(callbackInfo != NULL)
				{
					ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
				}
				return;
			}
			ACCESS_MASK DuplicatedRights = OperationInformation->Parameters->DuplicateHandleInformation.GrantedAccess;
			callbackInfo->DesiredAccess = DuplicatedRights;
			callbackInfo->OperationType = 2;
			break;
		}
	}

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	
	status = PsCreateSystemThread(&hPostHandleWorkerThread, THREAD_ALL_ACCESS, &objectAttributes, NULL, NULL, (PKSTART_ROUTINE)PostHandleWorkerThread, callbackInfo);
	if (!NT_SUCCESS(status)) {
		DbgPrint("PsCreateSystemThread failed: %x\n", status);
		ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
		goto Exit;
	}
Exit:
	if(hPostHandleWorkerThread != NULL)
	{
		ZwClose(hPostHandleWorkerThread);
	}
	return;
}

// [DONE]
// Callback to capture process termination events
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void TerminateProcessNotifyRoutine(
	_In_ HANDLE ParentProcessId, 
	_In_ HANDLE ProcessId, 
	_In_ BOOLEAN Create
)
{
	NTSTATUS status;
	UNICODE_STRING targetImagePath{};
	UNICODE_STRING sourceImagePath{};

	HANDLE sourcePID = NULL;
	HANDLE targetPID = NULL;
	FILETIME fileTime;

	PAGED_CODE();
	UNREFERENCED_PARAMETER(ParentProcessId);
	UNREFERENCED_PARAMETER(ProcessId);

	if (!Create)
	{
		KeQuerySystemTime(&fileTime);

		targetPID = ProcessId;
		sourcePID = ParentProcessId;

		ULONGLONG uTargetPID = HandleToULong(targetPID);
		ULONGLONG uSourcePID = HandleToULong(sourcePID);
		ULONGLONG sourceThreadId = HandleToULong(PsGetCurrentThreadId());

		sourceImagePath.Length = 0;
		sourceImagePath.MaximumLength = MAX_ALLOC;
		sourceImagePath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, sourceImagePath.MaximumLength, CALBACK_TAG);
		status = GetProcessImageName(sourcePID, &sourceImagePath);
		if (status != STATUS_SUCCESS) {
			sourceImagePath.Buffer = NULL;
		}

		targetImagePath.Length = 0;
		targetImagePath.MaximumLength = MAX_ALLOC;
		targetImagePath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, targetImagePath.MaximumLength, CALBACK_TAG);
		status = GetProcessImageName(targetPID, &targetImagePath);
		if (status != STATUS_SUCCESS) {
			targetImagePath.Buffer = NULL;
		}

		EventWriteProcessTerminate(NULL, &fileTime, sourceImagePath.Buffer, uSourcePID, sourceThreadId, targetImagePath.Buffer, uTargetPID);
		goto Exit;
	}
Exit:
	if (targetImagePath.Buffer != NULL) {
		ExFreePoolWithTag(targetImagePath.Buffer, CALBACK_TAG);
	}

	if (sourceImagePath.Buffer != NULL) {
		ExFreePoolWithTag(sourceImagePath.Buffer, CALBACK_TAG);
	}
}