#include "registry.h"
#include "shared.h"
#include "process.h"
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
		DbgPrint("GetRegistryKeyPath - ExAllocatePool2 failed. Status 0x%x", status);
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