#include "process.h"
#include "token.h"

PAGED_FILE();

ZWQUERYINFORMATIONPROCESS ZwQueryInformationProcess;

NTSTATUS GetProcessImageName(HANDLE processId, PUNICODE_STRING ProcessImageName)
{
	//Add NtQueryInformationProcess - https://stackoverflow.com/questions/3707133/how-to-use-zwqueryinformationprocess-to-get-processimagefilename-in-a-kernel-dri
	PAGED_CODE();
	NTSTATUS status;
	ULONG returnedLength;
	ULONG bufferLength;
	HANDLE hProcess = NULL;
	PVOID buffer{};
	PEPROCESS eProcess;
	//PUNICODE_STRING imageName;
	UNICODE_STRING routineName;

	status = PsLookupProcessByProcessId(processId, &eProcess);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	status = ObOpenObjectByPointer(
		eProcess, 
		OBJ_KERNEL_HANDLE, NULL,
		0, 
		0, 
		KernelMode, 
		&hProcess);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	ObDereferenceObject(eProcess);

	if (!ZwQueryInformationProcess) {

		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

		ZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);

		if (ZwQueryInformationProcess == NULL) {
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
			return STATUS_NOT_FOUND;
		}
	}

	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &returnedLength);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		goto Exit;
	}


	bufferLength = returnedLength;
	if (ProcessImageName->MaximumLength < bufferLength)
	{
		ProcessImageName->MaximumLength = (USHORT)bufferLength;
		return STATUS_BUFFER_OVERFLOW;
	}

	buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferLength, PROCESS_TAG);

	if (buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, buffer, bufferLength, &bufferLength);

	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	//imageName = (PUNICODE_STRING)buffer;
	RtlCopyUnicodeString(ProcessImageName, (PUNICODE_STRING)buffer);

	//Adding null terminator
	ProcessImageName->Buffer[ProcessImageName->Length / sizeof(UNICODE_NULL)] = UNICODE_NULL;

Exit:
	if(hProcess != NULL)
	{
		ZwClose(hProcess);
	}
	if (buffer != NULL)
	{
		ExFreePoolWithTag(buffer, PROCESS_TAG);
	}
	return status;
}
NTSTATUS GetProcessToken(HANDLE processId, PHANDLE hToken) {
	PAGED_CODE();
	NTSTATUS status;
	PEPROCESS eProcess;
	HANDLE hProcess = NULL;
	HANDLE htok = NULL;
	status = PsLookupProcessByProcessId(processId, &eProcess);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	status = ObOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, NULL, 0, 0, KernelMode, &hProcess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
		goto Exit;
	}
	ObDereferenceObject(eProcess);
	status = ZwOpenProcessTokenEx(hProcess, TOKEN_QUERY, OBJ_KERNEL_HANDLE, &htok);
	if (!NT_SUCCESS(status) || htok == NULL) {
		DbgPrint("ZwOpenProcessTokenEx Failed: %08x\n", status);
		goto Exit;
	}

Exit:
	if (htok == NULL) {
		status = STATUS_UNSUCCESSFUL;
	}
	*hToken = htok;
	if (hProcess != NULL)
	{
		ZwClose(hProcess);
	}
	return status;
}