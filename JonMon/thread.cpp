#include "thread.h"
#include "token.h"

PAGED_FILE();

NTSTATUS GetThreadHandle(CLIENT_ID ThreadId, PHANDLE hToken) {
	HANDLE handleToken = NULL;
	HANDLE hThread = NULL;
	NTSTATUS status;
	OBJECT_ATTRIBUTES attr = { 0 };

	PAGED_CODE();
	status = ZwOpenThread(&hThread, 0x0040, &attr, &ThreadId);
	status = ZwOpenThreadTokenEx(hThread, TOKEN_ALL_ACCESS, TRUE, OBJ_KERNEL_HANDLE, &handleToken);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}
Exit:
	*hToken = handleToken;
	if(hThread != NULL)
	{
		ZwClose(hThread);
	}
	return status;
}

// Define the process object and thread object structures
VOID GetThreadToken(HANDLE hThread) {
	HANDLE hToken = NULL;
	NTSTATUS status;
	PTOKEN_STATISTICS pTokenInfo = NULL;
	ULONG returnLength;

	PAGED_CODE();
	
	//DbgPrint("Getting Thread Token\n");
	status = ZwOpenProcessTokenEx(hThread, TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hToken);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}

	status = ZwQueryInformationToken(hToken, TokenStatistics, NULL, 0, &returnLength);
	pTokenInfo = (PTOKEN_STATISTICS)ExAllocatePool2(POOL_FLAG_PAGED, returnLength, THREAD_TAG);

	if (pTokenInfo == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag Failed: %08x\n", status);
		goto Exit;
	}
	status = ZwQueryInformationToken(hToken, TokenStatistics, pTokenInfo, returnLength, &returnLength);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwQueryInformationToken Failed: %08x\n", status);
		goto Exit;
	}
	DbgPrint("Token Type: %d\n", pTokenInfo->TokenType);


Exit:
	if (pTokenInfo != NULL) {
		ExFreePoolWithTag(pTokenInfo, THREAD_TAG);
	}
	if (hToken != NULL) {
		ZwClose(hToken);
	}
	
	return;

}

//Crashing for some reason here - debug. 
NTSTATUS GetThreadImpersonationLevel(PETHREAD thread, PSECURITY_IMPERSONATION_LEVEL ImpersonationLevel, PUNICODE_STRING ImpersonationName) {
	PAGED_CODE();
	PACCESS_TOKEN token = NULL;
	BOOLEAN copyOnOpen;
	BOOLEAN effectiveOnly;
	SECURITY_IMPERSONATION_LEVEL impersonationLevel;
	NTSTATUS status = STATUS_ABANDONED;
	token = PsReferenceImpersonationToken(thread, &copyOnOpen, &effectiveOnly, &impersonationLevel);
	if (token == NULL) {
		return STATUS_NO_TOKEN;
	}
	else {
		*ImpersonationLevel = impersonationLevel;
		UNICODE_STRING ImpersonationString{};
		switch (impersonationLevel) {
			case SecurityImpersonation:
			{
				RtlInitUnicodeString(&ImpersonationString, L"SecurityImpersonation");
				break;
			}
			case SecurityDelegation:
			{
				RtlInitUnicodeString(&ImpersonationString, L"SecurityDelegation");
				break;
			}
			default:
			{
				break;
			}
		}
		if (ImpersonationString.Buffer != NULL) {
			RtlCopyUnicodeString(ImpersonationName, &ImpersonationString);
			status = STATUS_SUCCESS;
		}
		
		PsDereferenceImpersonationToken(token);
		return status;
	}
}

//
// JonMonToDo: Update unicode_strings to properly clear. Also need to re-write because I am doing SourceThreadId and passing in CLIENT_ID. 
//

NTSTATUS ThreadImpersonationEvent(HANDLE hToken, PETHREAD eThread, PCWSTR OperationType, WCHAR* RequestorImagePath, ULONGLONG USourceProcessId, ULONGLONG sourceProcStartKey, ULONGLONG UTargetProcessId, ULONGLONG targetProcStartKey) {
	UNREFERENCED_PARAMETER(OperationType);
	UNREFERENCED_PARAMETER(UTargetProcessId);
	UNREFERENCED_PARAMETER(targetProcStartKey);
	UNICODE_STRING SourceFullUserName{}, ProcessIntegrityLevel{}, ThreadIntegrityLevel{}, ImpersonatedUser{}, ImpersonationString{};
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	FILETIME fileTime;
	ULONGLONG SourceThreadId = HandleToULong(PsGetThreadId(eThread));
	CLIENT_ID sourceClientId;
	sourceClientId.UniqueProcess = (HANDLE)USourceProcessId;
	sourceClientId.UniqueThread = (HANDLE)SourceThreadId;
	HANDLE hThreadToken = NULL;
	PAGED_CODE();
	
	/*
	* Update function to only write event if the target and source user are different or the integrity levels are different
	*/
	SourceFullUserName.Length = 0;
	SourceFullUserName.MaximumLength = MAX_ALLOC;
	SourceFullUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, THREAD_TAG);
	NTSTATUS status = GetTokenUserName(hToken, &SourceFullUserName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("GetTokenUserName Failed: %08x\n", status);
		goto Exit;
	}
	
	status = GetTokenIntegrityLevel(hToken, &ProcessIntegrityLevel);
	if (!NT_SUCCESS(status)) {
		DbgPrint("GetTokenIntegrityLevel Failed: %08x\n", status);
		goto Exit;
	}

	KeQuerySystemTime(&fileTime);
	if (eThread != NULL) {
		status = GetThreadHandle(sourceClientId, &hThreadToken);
		if (!NT_SUCCESS(status) || hThreadToken == NULL) {
			goto Exit;
		}

		ImpersonatedUser.Length = 0;
		ImpersonatedUser.MaximumLength = MAX_ALLOC;
		ImpersonatedUser.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, THREAD_TAG);
		status = GetTokenUserName(hThreadToken, &ImpersonatedUser);
		if (!NT_SUCCESS(status)) {
			DbgPrint("GetTokenUserName Failed: %08x\n", status);
			ImpersonatedUser.Buffer = NULL;
		}

		status = GetTokenIntegrityLevel(hThreadToken, &ThreadIntegrityLevel);
		if (!NT_SUCCESS(status)) {
			DbgPrint("GetTokenIntegrityLevel Failed: %08x\n", status);
			ImpersonatedUser.Buffer = NULL;
		}
		ImpersonationString.Length = 0;
		ImpersonationString.MaximumLength = MAX_ALLOC;
		ImpersonationString.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, THREAD_TAG);
		status = GetThreadImpersonationLevel(eThread, &ImpersonationLevel, &ImpersonationString);
		if (!NT_SUCCESS(status)) {
			goto Exit;
		}
		EventWriteImpersonationAction(NULL, &fileTime, RequestorImagePath, USourceProcessId, sourceProcStartKey, ProcessIntegrityLevel.Buffer, SourceFullUserName.Buffer, SourceThreadId, ImpersonationLevel, ImpersonationString.Buffer, ImpersonatedUser.Buffer, ThreadIntegrityLevel.Buffer, OperationType);
	}
	

Exit: 
	if (SourceFullUserName.Buffer != NULL)
	{
		ExFreePoolWithTag(SourceFullUserName.Buffer, THREAD_TAG);
	}
	if (ImpersonationString.Buffer != NULL)
	{
		ExFreePoolWithTag(ImpersonationString.Buffer, THREAD_TAG);
	}
	if (ImpersonatedUser.Buffer != NULL)
	{
		ExFreePoolWithTag(ImpersonatedUser.Buffer, THREAD_TAG);
	}
	if (hThreadToken != NULL)
	{
		ZwClose(hThreadToken);
	}
	return status;
}
