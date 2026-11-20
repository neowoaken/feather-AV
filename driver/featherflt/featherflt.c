/*
 * featherflt - minimal, read-only filesystem minifilter.
 *
 * The driver observes file creates/writes and keeps a small circular log of
 * accesses to executable-looking files. It never blocks, modifies or deletes
 * anything: Feather AV remains a classifier, never an auto-remediator.
 *
 * User mode can query state through the FeatherFltPort communication port.
 */

#include <fltKernel.h>

#define FEATHER_PORT_NAME      L"\\FeatherFltPort"
#define FEATHER_MAX_EVENTS     64
#define FEATHER_PATH_MAX       520

#define FEATHER_MSG_STATUS     1
#define FEATHER_MSG_EVENTS     2
#define FEATHER_MSG_CLEAR      3

typedef struct _FEATHER_EVENT {
    ULONG ProcessId;
    ULONG Length;
    WCHAR Path[FEATHER_PATH_MAX];
} FEATHER_EVENT;

typedef struct _FEATHER_STATUS {
    ULONG Loaded;
    ULONG EventCount;
    ULONG Dropped;
    ULONG Version;
} FEATHER_STATUS;

typedef struct _FEATHER_GLOBALS {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    KSPIN_LOCK Lock;
    FEATHER_EVENT Events[FEATHER_MAX_EVENTS];
    ULONG Head;
    ULONG Count;
    ULONG Dropped;
} FEATHER_GLOBALS;

static FEATHER_GLOBALS Globals;

static const WCHAR *ExecutableExtensions[] = {
    L".exe", L".dll", L".sys", L".drv", L".ocx", L".cpl",
    L".bat", L".cmd", L".ps1", L".vbs", L".js", L".jse",
    L".wsf", L".wsh", L".scr", L".com", L".msi", L".msp",
    L".hta", L".jar", L".lnk"
};

static BOOLEAN IsExecutableExtension(_In_ PUNICODE_STRING Extension)
{
    ULONG i;
    if (Extension == NULL || Extension->Length == 0) return FALSE;
    for (i = 0; i < sizeof(ExecutableExtensions) / sizeof(ExecutableExtensions[0]); ++i) {
        UNICODE_STRING wanted;
        RtlInitUnicodeString(&wanted, ExecutableExtensions[i]);
        if (RtlEqualUnicodeString(Extension, &wanted, TRUE)) return TRUE;
    }
    return FALSE;
}

static VOID LogExecutableAccess(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    PFLT_FILE_NAME_INFORMATION info = NULL;
    NTSTATUS status;
    KIRQL oldIrql;
    ULONG index;
    FEATHER_EVENT *event;

    if (FltObjects->FileObject == NULL) return;

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &info);
    if (!NT_SUCCESS(status)) return;

    status = FltParseFileNameInformation(info);
    if (!NT_SUCCESS(status) || !IsExecutableExtension(&info->Extension)) {
        FltReleaseFileNameInformation(info);
        return;
    }

    KeAcquireSpinLock(&Globals.Lock, &oldIrql);

    if (Globals.Count == FEATHER_MAX_EVENTS) {
        Globals.Head = (Globals.Head + 1) % FEATHER_MAX_EVENTS;
        ++Globals.Dropped;
    }
    index = (Globals.Head + Globals.Count) % FEATHER_MAX_EVENTS;
    if (Globals.Count < FEATHER_MAX_EVENTS) ++Globals.Count;

    event = &Globals.Events[index];
    event->ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    event->Length = info->Name.Length;
    if (event->Length > sizeof(event->Path) - sizeof(WCHAR)) {
        event->Length = sizeof(event->Path) - sizeof(WCHAR);
    }
    RtlCopyMemory(event->Path, info->Name.Buffer, event->Length);
    event->Path[event->Length / sizeof(WCHAR)] = L'\0';

    KeReleaseSpinLock(&Globals.Lock, oldIrql);
    FltReleaseFileNameInformation(info);
}

FLT_PREOP_CALLBACK_STATUS FeatherPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    LogExecutableAccess(Data, FltObjects);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FeatherPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    LogExecutableAccess(Data, FltObjects);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS FeatherInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

NTSTATUS FeatherInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

NTSTATUS FeatherUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (Globals.ServerPort != NULL) {
        FltCloseCommunicationPort(Globals.ServerPort);
        Globals.ServerPort = NULL;
    }
    if (Globals.Filter != NULL) {
        FltUnregisterFilter(Globals.Filter);
        Globals.Filter = NULL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS FLTAPI FeatherPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerCookie,
    _In_reads_bytes_opt_(Length) PVOID ConnectionCookie,
    _In_ ULONG Length,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerCookie);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(Length);
    if (ConnectionPortCookie != NULL) *ConnectionPortCookie = NULL;
    Globals.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID FLTAPI FeatherPortDisconnect(_In_opt_ PVOID PortCookie)
{
    UNREFERENCED_PARAMETER(PortCookie);
    Globals.ClientPort = NULL;
}

NTSTATUS FLTAPI FeatherPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnLength)
{
    ULONG kind;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(PortCookie);

    if (InputBuffer == NULL || InputBufferLength < sizeof(ULONG) || ReturnLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    kind = *(PULONG)InputBuffer;
    *ReturnLength = 0;

    if (kind == FEATHER_MSG_CLEAR) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&Globals.Lock, &oldIrql);
        Globals.Head = 0;
        Globals.Count = 0;
        Globals.Dropped = 0;
        KeReleaseSpinLock(&Globals.Lock, oldIrql);
        return STATUS_SUCCESS;
    }

    if (kind == FEATHER_MSG_STATUS) {
        FEATHER_STATUS status;
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(status)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        status.Loaded = 1;
        status.Version = 1;
        KeAcquireSpinLock(&Globals.Lock, &oldIrql);
        status.EventCount = Globals.Count;
        status.Dropped = Globals.Dropped;
        KeReleaseSpinLock(&Globals.Lock, oldIrql);
        RtlCopyMemory(OutputBuffer, &status, sizeof(status));
        *ReturnLength = sizeof(status);
        return STATUS_SUCCESS;
    }

    if (kind == FEATHER_MSG_EVENTS) {
        KIRQL oldIrql;
        ULONG i, n;
        if (OutputBuffer == NULL) return STATUS_INVALID_PARAMETER;
        KeAcquireSpinLock(&Globals.Lock, &oldIrql);
        n = Globals.Count;
        for (i = 0; i < n; ++i) {
            ULONG src = (Globals.Head + i) % FEATHER_MAX_EVENTS;
            ULONG offset = i * sizeof(FEATHER_EVENT);
            if (offset + sizeof(FEATHER_EVENT) > OutputBufferLength) break;
            RtlCopyMemory((PUCHAR)OutputBuffer + offset, &Globals.Events[src], sizeof(FEATHER_EVENT));
        }
        *ReturnLength = i * sizeof(FEATHER_EVENT);
        KeReleaseSpinLock(&Globals.Lock, oldIrql);
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
}

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, FeatherPreCreate, NULL },
    { IRP_MJ_WRITE,  0, FeatherPreWrite,  NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    FeatherUnload,
    FeatherInstanceSetup,
    FeatherInstanceQueryTeardown,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&Globals.Lock);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &Globals.Filter);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&portName, FEATHER_PORT_NAME);
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(Globals.Filter);
        Globals.Filter = NULL;
        return status;
    }

    InitializeObjectAttributes(&oa, &portName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
    status = FltCreateCommunicationPort(Globals.Filter, &Globals.ServerPort, &oa,
        NULL, FeatherPortConnect, FeatherPortDisconnect, FeatherPortMessage, 1);
    FltFreeSecurityDescriptor(sd);

    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(Globals.Filter);
    }

    if (!NT_SUCCESS(status)) {
        if (Globals.ServerPort != NULL) {
            FltCloseCommunicationPort(Globals.ServerPort);
            Globals.ServerPort = NULL;
        }
        FltUnregisterFilter(Globals.Filter);
        Globals.Filter = NULL;
    }

    return status;
}
