#include "minifilter.h"
#include "process.h"

PAGED_FILE();

PFLT_FILTER gFilterHandle;

NTSTATUS 
JonMonFilterUnload
(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
) 
{
    PAGED_CODE();
    NTSTATUS status;
    DbgPrint("In JonMonFilterUnload\n");
    if (Flags == FLTFL_FILTER_UNLOAD_MANDATORY) {
        FltUnregisterFilter(gFilterHandle);
        status = STATUS_SUCCESS;
    }
    else {
        status = STATUS_FLT_DO_NOT_DETACH;
    }
    return status;
}

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
    ULONGLONG sourceProcStartKey = PsGetProcessStartKey(PsGetCurrentProcess());
    FILETIME filetime;
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
    

    if (Data->RequestorMode != UserMode) {
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

            status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
            if (!NT_SUCCESS(status)) {
                goto Exit;
            }

            TraceLoggingWrite(
                g_hJonMon,
                "FileCreate",
                TraceLoggingInt32(10, "EventID"),
                TraceLoggingValue(sourceThreadId, "SourceThreadId"),
                TraceLoggingValue(currentProcessId, "SourceProcessId"),
                TraceLoggingValue(sourceProcStartKey, "SourceProcStartKey"),
                TraceLoggingWideString(fileNameInfo->Name.Buffer, "FileName"),
                TraceLoggingFileTime(filetime, "EventTime")
                );


            break;

        }
        case FILE_OPENED:
        {
            

            if (FltObjects->FileObject->Flags & FO_MAILSLOT)
            {
                DWORD RequestedRights = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

                status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
                if (!NT_SUCCESS(status)) {
                    goto Exit;
                }
                
                TraceLoggingWrite(
                    g_hJonMon,
                    "MailslotOpen",
                    TraceLoggingInt32(14, "EventID"),
                    TraceLoggingValue(sourceThreadId, "SourceThreadId"),
                    TraceLoggingValue(currentProcessId, "SourceProcessId"),
                    TraceLoggingValue(sourceProcStartKey, "SourceProcStartKey"),
                    TraceLoggingWideString(fileNameInfo->Name.Buffer, "FileName"),
                    TraceLoggingValue(RequestedRights, "RequestedRights"),
                    TraceLoggingFileTime(filetime, "EventTime")
				);
                
				break;

            }
            if (FltObjects->FileObject->Flags & FO_NAMED_PIPE)
            {
                DWORD RequestedRights = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

                status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
                if (!NT_SUCCESS(status)) {
                    goto Exit;
                }

                TraceLoggingWrite(
                    g_hJonMon,
                    "NamedPipeConnection",
                    TraceLoggingInt32(12, "EventID"),
                    TraceLoggingValue(sourceThreadId, "SourceThreadId"),
                    TraceLoggingValue(currentProcessId, "SourceProcessId"),
                    TraceLoggingValue(sourceProcStartKey, "SourceProcStartKey"),
                    TraceLoggingWideString(fileNameInfo->Name.Buffer, "FileName"),
                    TraceLoggingValue(RequestedRights, "RequestedRights"),
                    TraceLoggingFileTime(filetime, "EventTime")
                );

                break;

            }

            break;
        }
        case FILE_SUPERSEDED:
        {
            if (Data->Iopb->TargetFileObject->FileName.Length == 0)
            {
                break;
            }
            status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[IRP_MJ_CREATE_NAMED_PIPE] Failed to get file info\n");
                goto Exit;
            }
            //
            // check to see if FileName is valid before proceeding
            //
            

            if (Data->Iopb->Parameters.Create.Options & FO_REMOTE_ORIGIN)
            {
                //
                // only print if fileNameInfo->Name.Buffer contains pipe
                //
                if (wcsstr(fileNameInfo->Name.Buffer, L"\\pipe\\") != NULL) {

                    TraceLoggingWrite(
						g_hJonMon,
						"RemoteNamedPipeConnection",
						TraceLoggingInt32(15, "EventID"),
						TraceLoggingFileTime(filetime, "EventTime"),
						TraceLoggingWideString(fileNameInfo->Name.Buffer, "FileName"),
						TraceLoggingValue(currentProcessId, "SourceProcessId"),
						TraceLoggingValue(sourceProcStartKey, "SourceProcStartKey"),
						TraceLoggingValue(sourceThreadId, "SourceThreadId")
					);
                    break;

                }
            }

            if (Data->Iopb->Parameters.Create.Options == (FO_REMOTE_ORIGIN | FO_SEQUENTIAL_ONLY | FO_CACHE_SUPPORTED)) {

                //
                // only print if fileNameInfo->Name.Buffer contains mailslot 
                //
                if (wcsstr(fileNameInfo->Name.Buffer, L"mailslot") != NULL) {

                    TraceLoggingWrite(
                        g_hJonMon,
                        "RemoteMailslotConnection",
                        TraceLoggingInt32(15, "EventID"),
                        TraceLoggingFileTime(filetime, "EventTime"),
                        TraceLoggingWideString(Data->Iopb->TargetFileObject->FileName.Buffer, "FileName"),
                        TraceLoggingValue(currentProcessId, "SourceProcessId"),
                        TraceLoggingValue(sourceProcStartKey, "SourceProcStartKey"),
                        TraceLoggingValue(sourceThreadId, "SourceThreadId")
                    );
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
        break;
    }
    case IRP_MJ_CREATE_NAMED_PIPE:
    {
        DWORD RequestedRights = Data->Iopb->Parameters.CreatePipe.SecurityContext->DesiredAccess;
        DWORD GrantedRights = Data->Iopb->Parameters.CreatePipe.SecurityContext->AccessState->PreviouslyGrantedAccess;
        if (Data->IoStatus.Information == FILE_CREATED || Data->IoStatus.Information ==  FILE_OPENED)
        {
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
                
                TraceLoggingWrite(
					g_hJonMon,
					"NamedPipeCreate",
					TraceLoggingInt32(11, "EventID"),
                    TraceLoggingValue(sourceThreadId, "SourceThreadId"),
                    TraceLoggingValue(currentProcessId, "SourceProcessId"),
                    TraceLoggingValue(sourceProcStartKey, "SourceProcStartKey"),
                    TraceLoggingWideString(fileNameInfo->Name.Buffer, "FileName"),
                    TraceLoggingValue(RequestedRights, "RequestedRights"),
                    TraceLoggingValue(GrantedRights, "GrantedRights"),
					TraceLoggingFileTime(filetime, "EventTime")	
				);


                break;
            }
            default:
            {
                break;
            }
            }
        }

        break;
    }
   
    case IRP_MJ_CREATE_MAILSLOT:
    {
        if (Data->IoStatus.Information == FILE_CREATED || Data->IoStatus.Information == FILE_OPENED) {
            DWORD RequestedRights = Data->Iopb->Parameters.CreateMailslot.SecurityContext->DesiredAccess;
            
            status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[IRP_MJ_CREATE_MAILSLOT] Failed to get file info\n");
                goto Exit;
            }
            
            switch (Data->IoStatus.Information)
            {
                case FILE_CREATED:
                {               
                    TraceLoggingWrite(
                        g_hJonMon,
                        "MailslotCreate",
                        TraceLoggingInt32(13, "EventID"),
                        TraceLoggingValue(sourceThreadId, "SourceThreadId"),
                        TraceLoggingValue(currentProcessId, "SourceProcessId"),
                        TraceLoggingValue(sourceProcStartKey, "SourceProcStartKey"),
                        TraceLoggingWideString(fileNameInfo->Name.Buffer, "FileName"), 
                        TraceLoggingValue(RequestedRights, "RequestedRights"),
                        TraceLoggingFileTime(filetime, "EventTime")
                     );

                    break;
                }
                default:
                {
                    break;
                }
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
    if(fileNameInfo != NULL)
	{
		FltReleaseFileNameInformation(fileNameInfo);
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
        IRP_MJ_CREATE_MAILSLOT,
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