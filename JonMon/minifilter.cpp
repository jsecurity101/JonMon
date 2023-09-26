#include "minifilter.h"
#include "thread.h"
#include "process.h"
#include "token.h"

PAGED_FILE();

PFLT_FILTER gFilterHandle;

NTSTATUS 
JonMonFilterUnload
(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
) {
    PAGED_CODE();
    NTSTATUS status;
    DbgPrint("In JonMonFilterUnload\n");
    if (Flags & FLTFL_FILTER_UNLOAD_MANDATORY) {
        FltUnregisterFilter(gFilterHandle);
        status = STATUS_SUCCESS;
    }
    else {
        status = STATUS_FLT_DO_NOT_DETACH;
    }
    return status;
}


/* 
From: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_post_operation_callback
Post-operation callback routines are called in an arbitrary thread context, at IRQL <= DISPATCH_LEVEL. Because this callback routine can be called at IRQL DISPATCH_LEVEL, it is subject to the following constraints:

It cannot safely call any kernel-mode routine that must run at a lower IRQL.
Any data structures used in this routine must be allocated from nonpaged pool.
It cannot be made pageable.
It cannot acquire resources, mutexes, or fast mutexes. However, it can acquire spin locks.
It cannot get, set, or delete contexts, but it can release contexts.
Any I/O completion processing that needs to be performed at IRQL < DISPATCH_LEVEL cannot be performed directly in the postoperation callback routine. Instead, it must be posted to a work queue by calling a routine such as FltDoCompletionProcessingWhenSafe or FltQueueDeferredIoWorkItem.


All memory allocation needs to be non-paged pool. 

To-Do: Update all functions to use non-paged pool.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
FLT_POSTOP_CALLBACK_STATUS 
FLTAPI 
FilterPostCallback
(
    _In_ PFLT_CALLBACK_DATA Data, 
    _In_ PCFLT_RELATED_OBJECTS FltObjects, 
    _In_ PVOID CompletionContext, 
    _In_ FLT_POST_OPERATION_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    HANDLE sourceThreadId = PsGetThreadId(Data->Thread);
    HANDLE currentProcessId = PsGetCurrentProcessId();
    UNICODE_STRING sourceImage{}, sourceUserName{}, sourceIntegrityLevel{};
    ULONGLONG sourceProcStartKey = PsGetProcessStartKey(PsGetCurrentProcess());
    FILETIME filetime;
    HANDLE sToken = NULL;
    NTSTATUS status;
    DWORD sourceAuthenticationId = 0;
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    

    if (Data->RequestorMode != UserMode) {
		goto Exit;
	}

    //
    //Checking IRQL for now until functions are using non-paged pool
    //

    if (KeGetCurrentIrql() == DISPATCH_LEVEL) {
		goto Exit;
	}

    if (currentProcessId == (HANDLE)4) {
		goto Exit;
	}

    //
    //go to exit if filename is null
    //
    if (Data->Iopb->TargetFileObject->FileName.Length == 0) {
		goto Exit;
	}

    KeQuerySystemTime(&filetime);


    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
    {
        switch (Data->IoStatus.Information) {
        case FILE_CREATED:
        {

            status = GetProcessToken(currentProcessId, &sToken);
            if (!NT_SUCCESS(status) || sToken == NULL)
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process token\n");
                goto Exit;
            }

            status = GetTokenIntegrityLevel(sToken, &sourceIntegrityLevel);
            if (!NT_SUCCESS(status) || sourceIntegrityLevel.Buffer == NULL)
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get token integrity level\n");
                goto Exit;
            }

            //
            // Check to make sure integrity level == System 
            //
            if (wcscmp(sourceIntegrityLevel.Buffer, L"System") == 0)
            {
                goto Exit;
            }
            
            sourceImage.Length = 0;
            sourceImage.MaximumLength = MAX_ALLOC;
            sourceImage.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);
            status = GetProcessImageName(currentProcessId, &sourceImage);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[IRP_MJ_CREATE] Failed to get process image name\n");
                goto Exit;
            }

            sourceUserName.Length = 0;
            sourceUserName.MaximumLength = MAX_ALLOC;
            sourceUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);

           status = GetProcessUserName(&sourceUserName, currentProcessId, &sourceAuthenticationId);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[IRP_MJ_CREATE] Failed to get process username\n");
                goto Exit;

            }

            status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }

            EventWriteFileCreate(NULL, &filetime, sourceImage.Buffer, reinterpret_cast<ULONGLONG>(currentProcessId), sourceProcStartKey, reinterpret_cast<ULONGLONG>(sourceThreadId), sourceUserName.Buffer, sourceAuthenticationId, sourceIntegrityLevel.Buffer, fileNameInfo->Name.Buffer);
            goto Exit;

        }

        default:
        {
            goto Exit;
        }

        }
        goto Exit;
    }
    case IRP_MJ_CREATE_NAMED_PIPE:
    {
        DWORD RequestedRights = Data->Iopb->Parameters.CreatePipe.SecurityContext->DesiredAccess;
        DWORD GrantedRights = Data->Iopb->Parameters.CreatePipe.SecurityContext->AccessState->PreviouslyGrantedAccess;
        if (Data->IoStatus.Information == FILE_CREATED || Data->IoStatus.Information ==  FILE_OPENED)
        {
            sourceImage.Length = 0;
            sourceImage.MaximumLength = MAX_ALLOC;
            sourceImage.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);
            status = GetProcessImageName(currentProcessId, &sourceImage);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[IRP_MJ_CREATE_NAMED_PIPE] Failed to get process image name\n");
                goto Exit;
            }

            sourceUserName.Length = 0;
            sourceUserName.MaximumLength = MAX_ALLOC;
            sourceUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);

            status = GetProcessUserName(&sourceUserName, currentProcessId, &sourceAuthenticationId);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[IRP_MJ_CREATE_NAMED_PIPE] Failed to get process username\n");
                goto Exit;

            }

            status = GetProcessToken(currentProcessId, &sToken);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[IRP_MJ_CREATE_NAMED_PIPE] Failed to get process token\n");
                goto Exit;
            }

            status = GetTokenIntegrityLevel(sToken, &sourceIntegrityLevel);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[IRP_MJ_CREATE_NAMED_PIPE] Failed to get token integrity level\n");
                goto Exit;
            }

            status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[IRP_MJ_CREATE_NAMED_PIPE] Failed to get file info\n");
                goto Exit;
            }

            switch (Data->IoStatus.Information) {
            case FILE_CREATED:
            {
                bool RemoteCreation = FALSE;
                if (FltObjects->FileObject->Flags & FO_REMOTE_ORIGIN) {
                    DbgPrint("  Creation request came from remote machine\n");
                    RemoteCreation = TRUE;
                }
                EventWriteNamedPipeCreate(NULL, &filetime, sourceImage.Buffer, reinterpret_cast<ULONGLONG>(currentProcessId), sourceProcStartKey, reinterpret_cast<ULONGLONG>(sourceThreadId), sourceUserName.Buffer, sourceAuthenticationId, sourceIntegrityLevel.Buffer, fileNameInfo->Name.Buffer, RemoteCreation, RequestedRights);
                goto Exit;
            }
            case FILE_OPENED:
            {
                EventWriteNamedPipeOpen(NULL, &filetime, sourceImage.Buffer, reinterpret_cast<ULONGLONG>(currentProcessId), sourceProcStartKey, reinterpret_cast<ULONGLONG>(sourceThreadId), sourceUserName.Buffer, sourceAuthenticationId, sourceIntegrityLevel.Buffer, fileNameInfo->Name.Buffer, RequestedRights, GrantedRights);
                goto Exit;
            }
            default:
            {
                goto Exit;
            }
            }
        }
        goto Exit;
    }
    case IRP_MJ_SET_INFORMATION:
    {
        if (Data->Iopb->TargetFileObject->FileName.Buffer == NULL) {
			goto Exit;
		}
        switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
        //
        // File Deletes
        //
        case FileDispositionInformation:
        {

            status = GetProcessToken(currentProcessId, &sToken);
            if (!NT_SUCCESS(status) || sToken == NULL)
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process token\n");
                goto Exit;
            }

            status = GetTokenIntegrityLevel(sToken, &sourceIntegrityLevel);
            if (!NT_SUCCESS(status) || sourceIntegrityLevel.Buffer == NULL)
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get token integrity level\n");
                goto Exit;
            }

            //
            // Check to make sure integrity level == System 
            //
            if (wcscmp(sourceIntegrityLevel.Buffer, L"System") == 0)
            {
				goto Exit;
			}

            sourceUserName.Length = 0;
            sourceUserName.MaximumLength = MAX_ALLOC;
            sourceUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);

            status = GetProcessUserName(&sourceUserName, currentProcessId, &sourceAuthenticationId);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process username\n");
                goto Exit;

            }

            sourceImage.Length = 0;
            sourceImage.MaximumLength = MAX_ALLOC;
            sourceImage.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);
            status = GetProcessImageName(currentProcessId, &sourceImage);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process image name\n");
                goto Exit;
            }

            

            status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }

            EventWriteFileDelete(NULL, &filetime, sourceImage.Buffer, reinterpret_cast<ULONGLONG>(currentProcessId), sourceProcStartKey, reinterpret_cast<ULONGLONG>(sourceThreadId), sourceUserName.Buffer, sourceAuthenticationId, sourceIntegrityLevel.Buffer, fileNameInfo->Name.Buffer);
            goto Exit;
        }
        //
        // File Deletes
        //
        case FileDispositionInformationEx:
        {
            status = GetProcessToken(currentProcessId, &sToken);
            if (!NT_SUCCESS(status) || sToken == NULL)
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process token\n");
                goto Exit;
            }

            status = GetTokenIntegrityLevel(sToken, &sourceIntegrityLevel);
            if (!NT_SUCCESS(status) || sourceIntegrityLevel.Buffer == NULL)
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get token integrity level\n");
                goto Exit;
            }

            //
            // Check to make sure integrity level == System 
            //
            if (wcscmp(sourceIntegrityLevel.Buffer, L"System") == 0)
            {
                goto Exit;
            }
            sourceImage.Length = 0;
            sourceImage.MaximumLength = MAX_ALLOC;
            sourceImage.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);
            status = GetProcessImageName(currentProcessId, &sourceImage);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process image name\n");
                goto Exit;
            }

            sourceUserName.Length = 0;
            sourceUserName.MaximumLength = MAX_ALLOC;
            sourceUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);

            status = GetProcessUserName(&sourceUserName, currentProcessId, &sourceAuthenticationId);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process username\n");
                goto Exit;

            }

            status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }

            EventWriteFileDelete(NULL, &filetime, sourceImage.Buffer, reinterpret_cast<ULONGLONG>(currentProcessId), sourceProcStartKey, reinterpret_cast<ULONGLONG>(sourceThreadId), sourceUserName.Buffer, sourceAuthenticationId, sourceIntegrityLevel.Buffer, fileNameInfo->Name.Buffer);
            goto Exit;
        }
        //
        // File Renames
        //
        case FileRenameInformation:
        {
            sourceImage.Length = 0;
            sourceImage.MaximumLength = MAX_ALLOC;
            sourceImage.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);
            status = GetProcessImageName(currentProcessId, &sourceImage);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process image name\n");
            }

            sourceUserName.Length = 0;
            sourceUserName.MaximumLength = MAX_ALLOC;
            sourceUserName.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, MAX_ALLOC, FILE_TAG);

            status = GetProcessUserName(&sourceUserName, currentProcessId, &sourceAuthenticationId);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process username\n");
                goto Exit;

            }

            status = GetProcessToken(currentProcessId, &sToken);
            if (!NT_SUCCESS(status) || sToken == NULL)
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get process token\n");
                goto Exit;
            }

            status = GetTokenIntegrityLevel(sToken, &sourceIntegrityLevel);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[IRP_MJ_SET_INFORMATION] Failed to get token integrity level\n");
                goto Exit;
            }

            status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }
            EventWriteFileRename(NULL, &filetime, sourceImage.Buffer, reinterpret_cast<ULONGLONG>(currentProcessId), sourceProcStartKey, reinterpret_cast<ULONGLONG>(sourceThreadId), sourceUserName.Buffer, sourceAuthenticationId, sourceIntegrityLevel.Buffer, fileNameInfo->Name.Buffer);
            goto Exit;
        }
        default:
        {
            break;
        }
        }
        break;
    }
    default:
    {
        break;
    }
    }

Exit:
    if (sourceImage.Buffer != NULL) {
        ExFreePool(sourceImage.Buffer);
    }
    if (sourceUserName.Buffer != NULL) {
        ExFreePool(sourceUserName.Buffer);
    }
    if (sToken != NULL)
    {
		ZwClose(sToken);
	}
    return FLT_POSTOP_FINISHED_PROCESSING;
};


//
// FilterPreCallback placeholder
//
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS 
FLTAPI 
FilterPreCallback
(
    _In_ PFLT_CALLBACK_DATA Data, 
    _In_ PCFLT_RELATED_OBJECTS FltObjects, 
    _In_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    PAGED_CODE();

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;

}


NTSTATUS
FltCallbackStart
(
   _In_ PDRIVER_OBJECT DriverObject
) 
{
    PAGED_CODE();
    NTSTATUS status;

    CONST FLT_OPERATION_REGISTRATION FileSystemOperationCallbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        NULL,
        FilterPostCallback
    },
    {
        IRP_MJ_CREATE_NAMED_PIPE,
        0,
        NULL,
        FilterPostCallback
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        NULL,
        FilterPostCallback
    },
    {
        IRP_MJ_OPERATION_END
    }
    };

    CONST FLT_REGISTRATION FilterRegistration = {
        sizeof(FLT_REGISTRATION),
        FLT_REGISTRATION_VERSION,
        FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS,
        NULL,
        FileSystemOperationCallbacks,
        JonMonFilterUnload,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
    };


    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &gFilterHandle
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed FltRegisterFilter\n");
        return status;
    }
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed FltStartFiltering\n");
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = nullptr;
    }

    return status;
}