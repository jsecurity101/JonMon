#include "driver.h"
#include "callbacks.h"
#include "process.h" 

extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegistryPath
) 
{
	EventRegisterJonMon();
	g_RegPath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED,
		RegistryPath->Length, DRIVER_TAG);

	if (g_RegPath.Buffer == NULL) {
		DbgPrint("Failed allocation\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_RegPath.Length = g_RegPath.MaximumLength = RegistryPath->Length;
	memcpy(g_RegPath.Buffer, RegistryPath->Buffer, g_RegPath.Length);

	DbgPrint("JonMon Driver Entry Called 0x%p\n", DriverObject);
	DbgPrint("Registry Path %wZ\n", g_RegPath);

	DriverObject->DriverUnload = JonMonUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = JonMonCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = JonMonCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = JonMonDeviceControl;

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"\\Device\\JonMon");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Error creating device: 0x%X\n", status);
		ExFreePool(g_RegPath.Buffer);
		return status;
	}
	DriverObject->DeviceObject = DeviceObject;
	DeviceObject->Flags |= DO_DIRECT_IO;

	UNICODE_STRING symlink;
	RtlInitUnicodeString(&symlink, L"\\??\\JonMon");
	status = IoCreateSymbolicLink(&symlink, &name);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Error creating device: 0x%X\n", status);
		ExFreePool(g_RegPath.Buffer);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	status = RegisterCallbacks(DriverObject, DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Error registering callbacks: 0x%X\n", status);
		ExFreePool(g_RegPath.Buffer);
		return status;
	}

	ExFreePool(g_RegPath.Buffer);
	return status;
}

NTSTATUS JonMonDeviceControl(
	_In_ PDEVICE_OBJECT, 
	_In_ PIRP Irp
) {
	auto irpSp = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_INVALID_DEVICE_REQUEST;
	auto& dic = irpSp->Parameters.DeviceIoControl;
	auto len = 0;
	switch (dic.IoControlCode) {
	case IOCTL_CHANGE_PROTECTION_LEVEL_PROCESS:
		ChangePPL();
	}
	return CompleteRequest(Irp, status, len);
}

VOID AlterPPL(
	_In_ ULONG PID,
	_In_ ULONG value
) {
	PEPROCESS pProcess = NULL;
	PPROCESS_SIGNATURE_PROTECTION pSignatureProtect = NULL;

	ULONG pid = PID;

	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NT_SUCCESS(status)) {
		DbgPrint("Changing PPL value for target PROCESS ID: %d\n", PID);
		pSignatureProtect = (PPROCESS_SIGNATURE_PROTECTION)(((ULONG_PTR)pProcess) + 0x878);
		if (value == 1) {
			pSignatureProtect->SignatureLevel = 0x11;
			pSignatureProtect->SectionSignatureLevel = 0x11;
			pSignatureProtect->Protection = { 1,0,3 };
		}
		if (value == 0)
		{
			pSignatureProtect->SignatureLevel = 0x0;
			pSignatureProtect->SectionSignatureLevel = 0x0;
			pSignatureProtect->Protection = { 0,0,0 };
		}

		DbgPrint("Process ID %d 's protection level has changed\n", PID);

		ObDereferenceObject(pProcess);
	}
}


VOID ChangePPL()
{
	UNICODE_STRING functionName;
	RtlInitUnicodeString(&functionName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&functionName);

	NTSTATUS status;
	ULONG bufferSize = 0;
	UNICODE_STRING processName, processPath;
	RtlInitUnicodeString(&processName, L"JonMon-Service.exe");
	RtlInitUnicodeString(&processPath, L"\\Windows\\JonMon-Service.exe");

	status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		return;
	}
	if (bufferSize) {
		PVOID info = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, DRIVER_TAG);
		if (info) {
			status = ZwQuerySystemInformation(SystemProcessInformation, info, bufferSize, &bufferSize);
			if (NT_SUCCESS(status)) {
				PSYSTEM_PROCESSES processInfo = (PSYSTEM_PROCESSES)info;
				UNICODE_STRING imagePath;
				imagePath.MaximumLength = 1024;
				imagePath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, 1024, DRIVER_TAG);
				if (imagePath.Buffer == NULL) {
					DbgPrint("Failed allocation\n");
					return;
				}
				int count = 0;
				do {
					do {
						if (RtlEqualUnicodeString(&processName, &processInfo->ProcessName, TRUE)) {
							status = GetProcessImageName((HANDLE)processInfo->ProcessId, &imagePath);
							if (wcsstr(imagePath.Buffer, processPath.Buffer) != NULL) {
								g_ServicePID = (ULONG)processInfo->ProcessId;
								AlterPPL(g_ServicePID, 1);
								count++;
								DbgPrint("Found JonMon-Service.exe\n");
							}
						}
						processInfo = (PSYSTEM_PROCESSES)((unsigned char*)processInfo + processInfo->NextEntryDelta);
					} while (processInfo->NextEntryDelta);
				} while (count != 1);
				ExFreePoolWithTag(imagePath.Buffer, DRIVER_TAG);
			}
			ExFreePoolWithTag(info, DRIVER_TAG);
		}
	}
}

//
//Function unloads the driver
//
VOID JonMonUnload(
	_In_ PDRIVER_OBJECT DriverObject
) {
	PAGED_CODE();
	EventUnregisterJonMon();

	AlterPPL(g_ServicePID, 0);

	CmUnRegisterCallback(Cookie);
	
	ObUnRegisterCallbacks(ProcessRegistrationHandle);
	DbgPrint((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PostProcessHandleCallback Unloaded\n"));

	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, TRUE);
	DbgPrint((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetCreateProcessNotifyRoutineEx Unloaded\n"));

	PsRemoveLoadImageNotifyRoutine(LoadImageRoutine);
	DbgPrint((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetLoadImageNotifyRoutine Unloaded\n"));

	PsRemoveCreateThreadNotifyRoutine(PsCreateThreadNotifyRoutine);
	DbgPrint((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetCreateThreadNotifyRoutine Unloaded\n"));

	
	PsSetCreateProcessNotifyRoutine(TerminateProcessNotifyRoutine, TRUE);
	DbgPrint((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "PsSetCreateProcessNotifyRoutine Unloaded\n"));

	//sleep for 5 seconds to allow worker threads to finish
	LARGE_INTEGER interval;
	interval.QuadPart = -(3 * 10000000);
	KeDelayExecutionThread(KernelMode, FALSE, &interval);

	UNICODE_STRING symlink;
	RtlInitUnicodeString(&symlink, L"\\??\\JonMon");
	IoDeleteSymbolicLink(&symlink);
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("JonMon Driver Unloaded\n");
}


//Function completes the driver requests
NTSTATUS CompleteRequest(
	PIRP Irp,
	NTSTATUS status,
	ULONG_PTR info
) {
	PAGED_CODE();
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

//Function handles the create and close requests. Function just points to CompleteRequest.
NTSTATUS JonMonCreateClose(
	_In_ PDEVICE_OBJECT,
	_In_ PIRP Irp
) {
	PAGED_CODE();
	return CompleteRequest(Irp);
}