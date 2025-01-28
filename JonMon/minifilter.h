#ifndef _MINIFILTER_
#define _MINIFILTER_
#include "shared.h"


extern PFLT_FILTER gFilterHandle;

NTSTATUS 
JonMonFilterUnload
(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);


_IRQL_requires_max_(PASSIVE_LEVEL)
FLT_POSTOP_CALLBACK_STATUS 
FLTAPI 
FilterPostCallback
(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS 
FLTAPI 
FilterPreCallback
(
    _In_ PFLT_CALLBACK_DATA Data, 
    _In_ PCFLT_RELATED_OBJECTS FltObjects, 
    _In_ PVOID* CompletionContext
);

NTSTATUS 
FltCallbackStart
( 
    _In_ PDRIVER_OBJECT DriverObject
);

#endif // !_MINIFILTER_