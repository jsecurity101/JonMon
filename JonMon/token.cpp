#include "token.h"

PAGED_FILE();

NTSTATUS GetTokenUserName(HANDLE hToken, PUNICODE_STRING pFullName) {
	ULONG returnLength;
	UNICODE_STRING SidString;
	WCHAR SidStringBuffer[64];
	PTOKEN_USER pTokenInfo = NULL;
	ULONG NameLength;
	ULONG DomainLength;
	UNICODE_STRING DomainName = { 0 };
	DomainName.Length = 0;
	DomainName.MaximumLength = MAX_ALLOC;
	UNICODE_STRING UserName = { 0 };
	UserName.Length = 0;
	UserName.MaximumLength = MAX_ALLOC;
	NTSTATUS status;
	PVOID domainBuffer{};
	PVOID userBuffer{};
	SID_NAME_USE SidNameUse;
	PSID pSid = NULL;

	domainBuffer = ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, TOKEN_TAG);
	if (domainBuffer == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}
	DomainName.Buffer = (PWSTR)domainBuffer;

	userBuffer = ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, TOKEN_TAG);
	if (userBuffer == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}
	UserName.Buffer = (PWSTR)userBuffer;

	if (hToken == NULL)
	{
		status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	status = ZwQueryInformationToken(hToken, TokenUser, NULL, 0, &returnLength);

	pTokenInfo = (PTOKEN_USER)ExAllocatePool2(POOL_FLAG_PAGED, returnLength, TOKEN_TAG);
	if (pTokenInfo == NULL)
	{
		goto Exit;
	}
	status = ZwQueryInformationToken(hToken, TokenUser, pTokenInfo, returnLength, &returnLength);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

	pSid = pTokenInfo->User.Sid;
	
	RtlZeroMemory(SidStringBuffer, sizeof(SidStringBuffer));
	SidString.Buffer = (PWCHAR)SidStringBuffer;
	SidString.MaximumLength = sizeof(SidStringBuffer);

	status = RtlConvertSidToUnicodeString(&SidString, pSid, FALSE);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	
	status = SecLookupAccountSid(pSid, &NameLength, &UserName, &DomainLength, &DomainName, &SidNameUse);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	RtlCopyUnicodeString(pFullName, &DomainName);
	RtlAppendUnicodeToString(pFullName, L"\\");
	RtlAppendUnicodeStringToString(pFullName, &UserName);
	//Adding null terminator
	pFullName->Buffer[pFullName->Length / sizeof(UNICODE_NULL)] = UNICODE_NULL;

Exit:
	if (pTokenInfo != NULL) {
		ExFreePoolWithTag(pTokenInfo, TOKEN_TAG);
	}
	if (domainBuffer != NULL) {
		ExFreePoolWithTag(domainBuffer, TOKEN_TAG);
	}
	if (userBuffer != NULL) {
		ExFreePoolWithTag(userBuffer, TOKEN_TAG);
	}
	
		
	return status;
}

NTSTATUS GetUserTokenStatistics(HANDLE hToken, DWORD* AuthenticationId) {
	PAGED_CODE();
	PTOKEN_STATISTICS pTokenInfo = NULL;
	ULONG returnLength;

	NTSTATUS status = ZwQueryInformationToken(hToken, TokenStatistics, NULL, 0, &returnLength);

	pTokenInfo = (PTOKEN_STATISTICS)ExAllocatePool2(POOL_FLAG_PAGED, returnLength, TOKEN_TAG);
	if (pTokenInfo == NULL)
	{
		goto Exit;
	}
	status = ZwQueryInformationToken(hToken, TokenStatistics, pTokenInfo, returnLength, &returnLength);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwQueryInformationToken Failed: %08x\n", status);
		ExFreePoolWithTag(pTokenInfo, TOKEN_TAG);
		return status;
	}
	LUID LogonId = pTokenInfo->AuthenticationId;
	*AuthenticationId = LogonId.LowPart;
	

Exit: 
	if (pTokenInfo != NULL) {
		ExFreePoolWithTag(pTokenInfo, TOKEN_TAG);
	}
	return status;
}

NTSTATUS GetProcessUserName(PUNICODE_STRING pFullName, HANDLE ProcessId, DWORD* AuthenticationId) {
	PAGED_CODE();
	HANDLE hToken = NULL;
	HANDLE hProcess = NULL;
	PEPROCESS eProcess = NULL;

	if (pFullName == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &eProcess);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	status = ObOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, NULL, 0x1000, 0, KernelMode, &hProcess);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	status = ZwOpenProcessTokenEx(hProcess, TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hToken);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}
	status = GetTokenUserName(hToken, pFullName);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}
	status = GetUserTokenStatistics(hToken, AuthenticationId);
	if (!NT_SUCCESS(status))
	{
		goto Exit;
	}

Exit: 
	if (eProcess != NULL) {
		ObDereferenceObject(eProcess);
	}
	if (hToken != NULL) {
		ZwClose(hToken);
	}
	if (hProcess != NULL) {
		ObCloseHandle(hProcess, KernelMode);
	}
	return status;
}

DWORD GetSessionIdFromToken(HANDLE hToken) {
	NTSTATUS status;
	DWORD sessionId;
	DWORD returnLength = 0;

	status = ZwQueryInformationToken(hToken, TokenSessionId, &sessionId, sizeof(sessionId), &returnLength);
	if (NT_SUCCESS(status)) {
		return sessionId;
	}
	return 0;
}

NTSTATUS GetImpersonationLevelFromToken(HANDLE hToken) {
	PTOKEN_STATISTICS pTokenInfo = NULL;
	ULONG returnLength;

	NTSTATUS status = ZwQueryInformationToken(hToken, TokenStatistics, NULL, 0, &returnLength);

	pTokenInfo = (PTOKEN_STATISTICS)ExAllocatePool2(POOL_FLAG_PAGED, returnLength, TOKEN_TAG);

	if (pTokenInfo == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag Failed: %08x\n", status);
		return status;
	}
	status = ZwQueryInformationToken(hToken, TokenStatistics, pTokenInfo, returnLength, &returnLength);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwQueryInformationToken Failed: %08x\n", status);
		ExFreePoolWithTag(pTokenInfo, TOKEN_TAG);
		return status;
	}
	else
	{
		TOKEN_TYPE TokenType = pTokenInfo->TokenType;
		if (TokenType == TokenImpersonation) {
			DbgPrint("Token Type: %d\n", TokenType);
		}
		else {
			DbgPrint("Token Type: %d\n", TokenType);
		}
		ExFreePoolWithTag(pTokenInfo, TOKEN_TAG);
		status = STATUS_SUCCESS;
		return status;
	}
}

NTSTATUS GetTokenIntegrityLevel(HANDLE hToken, PUNICODE_STRING IntegrityLevel) {
	NTSTATUS status;
	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	ULONG returnLength;

	status = ZwQueryInformationToken(hToken, TokenIntegrityLevel, NULL, 0, &returnLength);

	pTIL = (PTOKEN_MANDATORY_LABEL)ExAllocatePool2(POOL_FLAG_PAGED, returnLength, TOKEN_TAG);

	if (pTIL == NULL)
	{
		goto Exit;
	}
	status = ZwQueryInformationToken(hToken, TokenIntegrityLevel, pTIL, returnLength, &returnLength);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwQueryInformationToken Failed: %08x\n", status);
		goto Exit;
	}

	ULONG IntegrityLevelValue = *RtlSubAuthoritySid(pTIL->Label.Sid, (DWORD)(UCHAR)(*RtlSubAuthorityCountSid(pTIL->Label.Sid) - 1));
	switch (IntegrityLevelValue) {
	case SECURITY_MANDATORY_UNTRUSTED_RID:
		RtlInitUnicodeString(IntegrityLevel, L"Untrusted");
		break;
	case SECURITY_MANDATORY_LOW_RID:
		RtlInitUnicodeString(IntegrityLevel, L"Low");
		break;
	case SECURITY_MANDATORY_MEDIUM_RID:
		RtlInitUnicodeString(IntegrityLevel, L"Medium");
		break;
	case SECURITY_MANDATORY_HIGH_RID:
		RtlInitUnicodeString(IntegrityLevel, L"High");
		break;
	case SECURITY_MANDATORY_SYSTEM_RID:
		RtlInitUnicodeString(IntegrityLevel, L"System");
		break;
	default:
		RtlInitUnicodeString(IntegrityLevel, L"Unknown");
		break;
	}
	status = STATUS_SUCCESS;

Exit:
	if(pTIL != NULL)
	{
		ExFreePoolWithTag(pTIL, TOKEN_TAG);
	}
	return status;
}