#include "registry.h"
#include "shared.h"
#include "token.h"
#include "process.h"
#include "thread.h"
#include <winerror.h>

PAGED_FILE();

NTSTATUS 
GetRegistryKeyPath(
	_In_ PVOID object, 
	_In_ ULONG tag, 
	_In_ PCWSTR* keyPath
) {
	PCUNICODE_STRING registryPath = NULL;
	NTSTATUS status;
	PWCHAR buffer = NULL;
	ULONG bufferSize;
	PAGED_CODE();

	status = CmCallbackGetKeyObjectIDEx(&Cookie, object, NULL, &registryPath, 0);
	if (!NT_SUCCESS(status) || registryPath == NULL) {
		DbgPrint("CmCallbackGetKeyObjectIDEx failed. Status 0x%x", status);
		goto Exit;
	}

	// Allocate a buffer for the registry path
	bufferSize = (registryPath->Length / sizeof(WCHAR)) + 1;

	buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, bufferSize * sizeof(WCHAR), tag);
	if (buffer == NULL) {
		DbgPrint("ExAllocatePool2 failed. Status 0x%x", status);
		goto Exit;
	}

	// Zero the buffer before copying the registry path and adding a null terminator
	RtlZeroMemory(buffer, bufferSize + sizeof(UNICODE_NULL));
	RtlCopyMemory(buffer, registryPath->Buffer, registryPath->Length);
	buffer[bufferSize - 1] = UNICODE_NULL;

	*keyPath = buffer;
	status = STATUS_SUCCESS;

Exit:
	if (registryPath != NULL) {
		CmCallbackReleaseKeyObjectIDEx(registryPath);
	}

	return status;
}

NTSTATUS 
GetRegistryEventInfo(
	_In_ HANDLE pid, 
	_In_ PUNICODE_STRING pRequestorImagePath, 
	_In_ PUNICODE_STRING pFullUserName, 
	_In_ PULONG pLogonId
) {
	// Get process image name
	pRequestorImagePath->Length = 0;
	pRequestorImagePath->MaximumLength = MAX_ALLOC;
	pRequestorImagePath->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, REGISTRY_TAG);
	NTSTATUS status = GetProcessImageName(pid, pRequestorImagePath);
	if (!NT_SUCCESS(status)) {
		DbgPrint("GetProcessImageName failed. Status 0x%x", status);
		pRequestorImagePath->Buffer = L"Unknown";
	}

	// Get process username and logon ID
	pFullUserName->Length = 0;
	pFullUserName->MaximumLength = MAX_ALLOC;
	pFullUserName->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, REGISTRY_TAG);
	*pLogonId = 0;
	status = GetProcessUserName(pFullUserName, pid, pLogonId);
	if (!NT_SUCCESS(status)) {
		DbgPrint("GetProcessUserName failed. Status 0x%x", status);
		pFullUserName->Buffer = L"Unknown";
	}

	return status;
} 

VOID 
DeleteKey(
	_In_ PVOID context, 
	_In_ PREG_DELETE_KEY_INFORMATION info
) {
	UNREFERENCED_PARAMETER(context);
	HANDLE Requestorpid = PsGetCurrentProcessId();
	UNICODE_STRING RequestorImagePath{};
	UNICODE_STRING FullUserName{};
	ULONG LogonId;
	ULONGLONG sourceProcStartKey = PsGetProcessStartKey(PsGetCurrentProcess());
	ULONGLONG USourceProcessId = HandleToULong(Requestorpid);
	ULONGLONG sourceThreadId = HandleToULong(PsGetCurrentThreadId());
	FILETIME fileTime;
	PCWSTR keyPath = NULL;
	NTSTATUS status;

	PAGED_CODE();

	status = GetRegistryKeyPath(info->Object, REGISTRY_TAG, &keyPath);
	if (keyPath == NULL) {
		goto Exit;
	}

	RequestorImagePath.Length = 0;
	RequestorImagePath.MaximumLength = MAX_ALLOC;
	RequestorImagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, REGISTRY_TAG);
	status = GetProcessImageName(Requestorpid, &RequestorImagePath);
	if (RequestorImagePath.Length == 0 || RequestorImagePath.Buffer ==	NULL)
	{
		//
		// fatal
		//
		if (keyPath != NULL) {
			ExFreePoolWithTag((PVOID)keyPath, REGISTRY_TAG);
		}
		return;
	}
	//
	// get the username and logon id of the process that is deleting the key
	//
	FullUserName.Length = 0;
	FullUserName.MaximumLength = MAX_ALLOC;
	FullUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, REGISTRY_TAG);
	LogonId = 0;
	status = GetProcessUserName(&FullUserName, Requestorpid, &LogonId);
	if (FullUserName.Length == 0 || FullUserName.Buffer == NULL)
	{
		//
		// fatal
		//
		if (keyPath != NULL) {
			ExFreePoolWithTag((PVOID)keyPath, REGISTRY_TAG);
		}
		if (RequestorImagePath.Buffer != NULL) {
			ExFreePoolWithTag(RequestorImagePath.Buffer, REGISTRY_TAG);
		}
		return;
	}

	KeQuerySystemTime(&fileTime);


	EventWriteRegistryDeleteKey(0, &fileTime, RequestorImagePath.Buffer, USourceProcessId, sourceThreadId, sourceProcStartKey, keyPath, FullUserName.Buffer, LogonId);

Exit:

	if (RequestorImagePath.Buffer != NULL) {
		ExFreePoolWithTag(RequestorImagePath.Buffer, REGISTRY_TAG);
	}
	if (FullUserName.Buffer != NULL) {
		ExFreePoolWithTag(FullUserName.Buffer, REGISTRY_TAG);
	}
	if (keyPath != NULL) {
		ExFreePoolWithTag((PVOID)keyPath, REGISTRY_TAG);
	}
	return;
}

VOID 
SendSetValueRegistryInfo(
	_In_ PVOID StartContext
) {

	NTSTATUS status = STATUS_SUCCESS;
	PCWSTR keyPath = NULL;
	UNICODE_STRING RequestorImagePath = { 0 };
	UNICODE_STRING FullUserName = { 0 };
	ULONG LogonId;
	HANDLE hToken = NULL;
	FILETIME fileTime;
	KeQuerySystemTime(&fileTime);

	PAGED_CODE();
	PREG_SET_VALUE_CALLBACK_INFO callbackInfo = (PREG_SET_VALUE_CALLBACK_INFO)StartContext;
	ULONGLONG sourceProcessId = HandleToULong(callbackInfo->SourceProcessId);
	ULONGLONG sourceThreadId = HandleToULong(callbackInfo->SourceThreadId);
	ULONGLONG sourceProcStartKey = PsGetProcessStartKey(callbackInfo->SourceProcess);
	keyPath = callbackInfo->KeyPath;
	PVOID data = callbackInfo->Data;

	if (data == NULL)
	{
		status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}

	//
	//reducing loud noise
	//
	if (wcsstr(keyPath, L"DeliveryOptimization\\Usage") != NULL) {
		goto Exit;
	}
	if (wcsstr(keyPath, L"\\DeliveryOptimization\\Config") != NULL) {
		goto Exit;
	}

	//
	//source image path
	//
	RequestorImagePath.Length = 0;
	RequestorImagePath.MaximumLength = MAX_ALLOC;
	RequestorImagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, REGISTRY_TAG);
	status = GetProcessImageName(callbackInfo->SourceProcessId, &RequestorImagePath);
	if (RequestorImagePath.Buffer == NULL)
	{
		goto Exit;
	}
	//
	// get the username and logon id of the process that is deleting the key
	//
	FullUserName.Length = 0;
	FullUserName.MaximumLength = MAX_ALLOC;
	FullUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, REGISTRY_TAG);
	LogonId = 0;
	status = GetProcessUserName(&FullUserName, callbackInfo->SourceProcessId, &LogonId);
	if (FullUserName.Buffer == NULL)
	{
		goto Exit;
	}

	//
	// Grabbing impersonation data
	//
	
	status = GetProcessToken((HANDLE)sourceProcessId, &hToken);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}
	DWORD SessionId = GetSessionIdFromToken(hToken);
	if (SessionId != 0) {
		status = ThreadImpersonationEvent(hToken, callbackInfo->SourceThread, L"RegSetValue", RequestorImagePath.Buffer, sourceProcessId, sourceProcStartKey, NULL, NULL);
	}
	
	//
	// End of querying for impersonation
	//

	switch (callbackInfo->Type) {
	case REG_DWORD:
	{
		////
		//// DWORD is 32-bits / 4 bytes
		////
		WCHAR buffer[11]; // Allocate space for up to 10 digits plus the null-terminator
		swprintf(buffer, L"%u", *(PULONG)data);

		EventWriteRegistrySetValue(0, &fileTime, RequestorImagePath.Buffer, sourceProcessId, sourceThreadId, sourceProcStartKey, keyPath, callbackInfo->ValueName.Buffer, buffer, L"REG_DWORD", FullUserName.Buffer, LogonId);

		goto Exit;
	}
	case REG_QWORD: 
	{
		////
		//// QWORD is 64-bits / 8 bytes
		////
		WCHAR buffer[21]; // Allocate space for up to 20 digits plus the null-terminator
		swprintf(buffer, L"%llu", *(PULONGLONG)data);


		EventWriteRegistrySetValue(0, &fileTime, RequestorImagePath.Buffer, sourceProcessId, sourceThreadId, sourceProcStartKey, keyPath, callbackInfo->ValueName.Buffer, buffer, L"REG_QWORD", FullUserName.Buffer, LogonId);
		goto Exit;
	}
	case REG_SZ:
	{
		//
		// Create a buffer to hold the string from data and null-terminate it
		//
		PWSTR buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, callbackInfo->DataSize + sizeof(WCHAR), REGISTRY_TAG);
		if (buffer == NULL)
		{
			status = STATUS_UNSUCCESSFUL;
			goto Exit;
		}
		RtlCopyMemory(buffer, data, callbackInfo->DataSize);
		buffer[callbackInfo->DataSize / sizeof(WCHAR)] = L'\0';
		EventWriteRegistrySetValue(0, &fileTime, RequestorImagePath.Buffer, sourceProcessId, sourceThreadId, sourceProcStartKey, keyPath, callbackInfo->ValueName.Buffer, buffer, L"REG_SZ", FullUserName.Buffer, LogonId);

		//
		// Free the buffer
		//
		ExFreePoolWithTag(buffer, REGISTRY_TAG);

		goto Exit;
	}
	default:
	{
		goto Exit;
	}
	}

Exit:
	if (RequestorImagePath.Buffer != NULL)
	{
		ExFreePoolWithTag(RequestorImagePath.Buffer, REGISTRY_TAG);
	}
	if (FullUserName.Buffer != NULL)
	{
		ExFreePoolWithTag(FullUserName.Buffer, REGISTRY_TAG);
	}
	if (keyPath != NULL)
	{
		ExFreePoolWithTag((PVOID)keyPath, SYSTEM_THREAD_TAG);
	}
	if (callbackInfo->ValueName.Buffer != NULL)
	{
		ExFreePoolWithTag(callbackInfo->ValueName.Buffer, SYSTEM_THREAD_TAG);
	}
	if (callbackInfo->Data != NULL) {
		ExFreePoolWithTag((PVOID)callbackInfo->Data, SYSTEM_THREAD_TAG);
	}
	if (callbackInfo != NULL)
	{
		ExFreePoolWithTag(StartContext, SYSTEM_THREAD_TAG);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
	return;
}

VOID 
CreateKey(
	_In_ PVOID StartContext
)
{
	NTSTATUS status;
	UNICODE_STRING fullUserName{};
	UNICODE_STRING sourceImagePath{};
	ULONG LogonId;
	FILETIME fileTime;
	KeQuerySystemTime(&fileTime);

	PAGED_CODE();

	PREG_CREATE_KEY_CALLBACK_INFO callbackInfo = (PREG_CREATE_KEY_CALLBACK_INFO)StartContext;
	if (callbackInfo == NULL)
	{
		goto Exit;
	}

	ULONGLONG sourceProcessId = HandleToULong(callbackInfo->SourceProcessId);
	ULONGLONG sourceThreadId = HandleToULong(callbackInfo->SourceThreadId);

	sourceImagePath.Length = 0;
	sourceImagePath.MaximumLength = MAX_ALLOC;
	sourceImagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, REGISTRY_TAG);
	status = GetProcessImageName(callbackInfo->SourceProcessId, &sourceImagePath);
	if (!NT_SUCCESS(status) || sourceImagePath.Buffer == NULL || sourceImagePath.Length == 0) {
		DbgPrint("GetProcessImageName failed. Status 0x%x", status);
		goto Exit;
	}

	fullUserName.Length = 0;
	fullUserName.MaximumLength = 520;
	fullUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, 520, REGISTRY_TAG);
	status = GetProcessUserName(&fullUserName, callbackInfo->SourceProcessId, &LogonId);
	if (!NT_SUCCESS(status) || fullUserName.Buffer == NULL || fullUserName.Length == 0) {
		DbgPrint("GetProcessUserName failed. Status 0x%x", status);
		goto Exit;
	}

	EventWriteRegistryCreateKey(0, &fileTime, sourceImagePath.Buffer, sourceProcessId, sourceThreadId, callbackInfo->ProcStartKey, callbackInfo->KeyPath.Buffer, callbackInfo->DesiredAccess, fullUserName.Buffer, LogonId);


	//
	// Grabbing impersonation data
	//
	HANDLE hToken = NULL;
	status = GetProcessToken((HANDLE)sourceProcessId, &hToken);
	if (NT_SUCCESS(status)) {
		DWORD SessionId = GetSessionIdFromToken(hToken);
		if (SessionId != 0) {
			status = ThreadImpersonationEvent(hToken, callbackInfo->SourceThread, L"RegCreateValue", sourceImagePath.Buffer, sourceProcessId, callbackInfo->ProcStartKey, NULL, NULL);

		}
		ZwClose(hToken);
	}
	//
	// End of querying for impersonation
	//


Exit:
	if (sourceImagePath.Buffer != NULL)
	{
		ExFreePoolWithTag(sourceImagePath.Buffer, REGISTRY_TAG);
	}
	if (fullUserName.Buffer != NULL)
	{
		ExFreePoolWithTag(fullUserName.Buffer, REGISTRY_TAG);
	}
	if (callbackInfo->KeyPath.Buffer != NULL) {
		ExFreePoolWithTag(callbackInfo->KeyPath.Buffer, REGISTRY_TAG);
	}
	if (callbackInfo != NULL)
	{
		ExFreePoolWithTag(callbackInfo, SYSTEM_THREAD_TAG);
	}
	return;
}

VOID 
SaveKey(
	_In_ PVOID context, 
	_In_ PREG_SAVE_KEY_INFORMATION info
) {
	HANDLE Requestorpid = PsGetCurrentProcessId();
	ULONGLONG sourceProcStartKey = PsGetProcessStartKey(PsGetCurrentProcess());
	UNICODE_STRING RequestorImagePath{};
	UNICODE_STRING FullUserName{};
	ULONG LogonId;
	ULONGLONG sourceProcessId = HandleToULong(Requestorpid);
	ULONGLONG sourceThreadId = HandleToULong(PsGetCurrentThreadId());
	FILETIME fileTime;
	PCWSTR keyPath = NULL;
	KeQuerySystemTime(&fileTime);
	NTSTATUS status;
	PAGED_CODE();
	UNREFERENCED_PARAMETER(context);

	
	if (info->Object != NULL && info->FileHandle != NULL) {
		status = GetRegistryKeyPath(info->Object, REGISTRY_TAG, &keyPath);
		if (keyPath == NULL) {
			goto Exit;
		}

		RequestorImagePath.Length = 0;
		RequestorImagePath.MaximumLength = MAX_ALLOC;
		RequestorImagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, REGISTRY_TAG);
		status = GetProcessImageName(Requestorpid, &RequestorImagePath);
		if (RequestorImagePath.Length == 0 || RequestorImagePath.Buffer == NULL)
		{
			//
			// fatal
			//
			if (keyPath != NULL) {
				ExFreePoolWithTag((PVOID)keyPath, REGISTRY_TAG);
			}
			return;
		}
		//
		// get the username and logon id of the process that is deleting the key
		//
		FullUserName.Length = 0;
		FullUserName.MaximumLength = MAX_ALLOC;
		FullUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, REGISTRY_TAG);
		LogonId = 0;
		status = GetProcessUserName(&FullUserName, Requestorpid, &LogonId);
		if (FullUserName.Length == 0 || FullUserName.Buffer == NULL)
		{
			//
			// fatal
			//
			if (keyPath != NULL) {
				ExFreePoolWithTag((PVOID)keyPath, REGISTRY_TAG);
			}
			if (RequestorImagePath.Buffer != NULL) {
				ExFreePoolWithTag(RequestorImagePath.Buffer, REGISTRY_TAG);
			}
			return;
		}

		EventWriteRegistrySaveKey(NULL, &fileTime, RequestorImagePath.Buffer, sourceProcessId, sourceThreadId, sourceProcStartKey, keyPath, FullUserName.Buffer, LogonId);
		
	}

Exit:
	if (RequestorImagePath.Buffer != NULL)
	{
		ExFreePoolWithTag(RequestorImagePath.Buffer, REGISTRY_TAG);
	}
	if (FullUserName.Buffer != NULL)
	{
		ExFreePoolWithTag(FullUserName.Buffer, REGISTRY_TAG);
	}
	if (keyPath != NULL) {
		ExFreePoolWithTag((PVOID)keyPath, REGISTRY_TAG);
	}
	return;
}