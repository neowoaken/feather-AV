/*
 * featherflt - on-access filesystem minifilter for Feather AV.
 *
 * On IRP_MJ_CREATE for executable-looking files the driver asks the Feather
 * real-time service for a verdict before allowing the open. A malicious or
 * unwanted verdict completes the create with STATUS_ACCESS_DENIED; the service
 * moves the file to quarantine before it replies. No file is wiped by the
 * kernel or by the service without a verdict.
 *
 * Failure policy: if the service is not connected, does not reply in time, or
 * returns an unknown verdict, the open is ALLOWED. This keeps the machine
 * bootable; the degraded state is counted and reported to the service so the
 * GUI can show it instead of pretending protection is active.
 */

#include <fltKernel.h>
#include "protocol.h"

#define FEATHER_MAX_EVENTS 64

typedef struct _FEATHER_GLOBALS {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;       // guarded by Lock
    HANDLE ServiceProcessId;    // guarded by Lock; excluded from scanning
    KSPIN_LOCK Lock;
    FEATHER_EVENT Events[FEATHER_MAX_EVENTS];
    ULONG Head;
    ULONG Count;
    ULONG Dropped;
    ULONG Timeouts;
    volatile LONG64 NextMessageId;
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

static VOID RecordEvent(
    _In_ ULONG64 MessageId,
    _In_ HANDLE ProcessId,
    _In_ ULONG Verdict,
    _In_ PFLT_FILE_NAME_INFORMATION Name)
{
    KIRQL oldIrql;
    FEATHER_EVENT *event;
    ULONG index;
    ULONG bytes = Name->Name.Length;

    if (bytes > sizeof(event->Path) - sizeof(WCHAR)) {
        bytes = sizeof(event->Path) - sizeof(WCHAR);
    }

    KeAcquireSpinLock(&Globals.Lock, &oldIrql);

    if (Globals.Count == FEATHER_MAX_EVENTS) {
        Globals.Head = (Globals.Head + 1) % FEATHER_MAX_EVENTS;
        ++Globals.Dropped;
    }
    index = (Globals.Head + Globals.Count) % FEATHER_MAX_EVENTS;
    if (Globals.Count < FEATHER_MAX_EVENTS) ++Globals.Count;

    event = &Globals.Events[index];
    event->MessageId = MessageId;
    event->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    event->PathLength = bytes;
    event->Verdict = Verdict;
    RtlCopyMemory(event->Path, Name->Name.Buffer, bytes);
    event->Path[bytes / sizeof(WCHAR)] = L'\0';

    KeReleaseSpinLock(&Globals.Lock, oldIrql);
}

static VOID NoteDegraded(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&Globals.Lock, &oldIrql);
    ++Globals.Timeouts;
    KeReleaseSpinLock(&Globals.Lock, oldIrql);
}

FLT_PREOP_CALLBACK_STATUS FeatherPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PFLT_PORT clientPort = NULL;
    HANDLE servicePid = NULL;
    FEATHER_SCAN_REQUEST request;
    FEATHER_SCAN_REPLY reply;
    LARGE_INTEGER timeout;
    ULONG replyLength = sizeof(reply);
    NTSTATUS status;
    ULONG64 messageId;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (FltObjects->FileObject == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Snapshot the service connection under the lock, then release it before
    // FltSendMessage (which synchronises port lifetime itself).
    KeAcquireSpinLock(&Globals.Lock, &oldIrql);
    clientPort = Globals.ClientPort;
    servicePid = Globals.ServiceProcessId;
    KeReleaseSpinLock(&Globals.Lock, oldIrql);

    if (clientPort == NULL) {
        NoteDegraded();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // The service opens the same file to hash/scan/quarantine it. Never ask it
    // to scan its own I/O, or we would recurse until the timeout.
    if (servicePid != NULL && PsGetCurrentProcessId() == servicePid) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status) || !IsExecutableExtension(&name->Extension)) {
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlZeroMemory(&request, sizeof(request));
    messageId = (ULONG64)InterlockedIncrement64(&Globals.NextMessageId);
    request.MessageId = messageId;
    request.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        request.DesiredAccess =
            Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    request.PathLength = name->Name.Length;
    if (request.PathLength > sizeof(request.Path) - sizeof(WCHAR)) {
        request.PathLength = sizeof(request.Path) - sizeof(WCHAR);
    }
    RtlCopyMemory(request.Path, name->Name.Buffer, request.PathLength);
    request.Path[request.PathLength / sizeof(WCHAR)] = L'\0';

    // Relative timeout: 20 seconds. Covers a full ClamAV stream scan; a hung
    // service degrades to fail-open rather than hanging the whole machine.
    timeout.QuadPart = -20 * 10000000LL;
    RtlZeroMemory(&reply, sizeof(reply));

    status = FltSendMessage(Globals.Filter,
                            &clientPort,
                            &request, sizeof(request),
                            &reply, &replyLength,
                            &timeout);

    if (!NT_SUCCESS(status) || replyLength < sizeof(reply)) {
        NoteDegraded();
        FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (reply.Verdict == FEATHER_VERDICT_BLOCK ||
        reply.Verdict == FEATHER_VERDICT_QUARANTINE) {

        RecordEvent(messageId, PsGetCurrentProcessId(), reply.Verdict, name);
        FltReleaseFileNameInformation(name);

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(name);
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
    switch (VolumeFilesystemType) {
    case FLT_FSTYPE_LANMAN:
    case FLT_FSTYPE_WEBDAV:
    case FLT_FSTYPE_NFS:
    case FLT_FSTYPE_MUP:
        return STATUS_FLT_DO_NOT_ATTACH;
    default:
        break;
    }
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
    KIRQL oldIrql;
    UNREFERENCED_PARAMETER(ServerCookie);
    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(Length);
    if (ConnectionPortCookie != NULL) *ConnectionPortCookie = NULL;

    KeAcquireSpinLock(&Globals.Lock, &oldIrql);
    Globals.ClientPort = ClientPort;
    Globals.ServiceProcessId = PsGetCurrentProcessId();
    KeReleaseSpinLock(&Globals.Lock, oldIrql);
    return STATUS_SUCCESS;
}

VOID FLTAPI FeatherPortDisconnect(_In_opt_ PVOID PortCookie)
{
    KIRQL oldIrql;
    UNREFERENCED_PARAMETER(PortCookie);
    KeAcquireSpinLock(&Globals.Lock, &oldIrql);
    Globals.ClientPort = NULL;
    Globals.ServiceProcessId = NULL;
    KeReleaseSpinLock(&Globals.Lock, oldIrql);
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
        KeAcquireSpinLock(&Globals.Lock, &oldIrql);
        Globals.Head = 0;
        Globals.Count = 0;
        Globals.Dropped = 0;
        Globals.Timeouts = 0;
        KeReleaseSpinLock(&Globals.Lock, oldIrql);
        return STATUS_SUCCESS;
    }

    if (kind == FEATHER_MSG_STATUS) {
        FEATHER_STATUS status;
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(status)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlZeroMemory(&status, sizeof(status));
        status.Loaded = 1;
        status.Version = FEATHER_PROTOCOL_VERSION;
        KeAcquireSpinLock(&Globals.Lock, &oldIrql);
        status.EventCount = Globals.Count;
        status.Dropped = Globals.Dropped;
        status.Timeouts = Globals.Timeouts;
        status.ServiceConnected = (Globals.ClientPort != NULL) ? 1 : 0;
        KeReleaseSpinLock(&Globals.Lock, oldIrql);
        RtlCopyMemory(OutputBuffer, &status, sizeof(status));
        *ReturnLength = sizeof(status);
        return STATUS_SUCCESS;
    }

    if (kind == FEATHER_MSG_EVENTS) {
        ULONG i, n;
        if (OutputBuffer == NULL) return STATUS_INVALID_PARAMETER;
        KeAcquireSpinLock(&Globals.Lock, &oldIrql);
        n = Globals.Count;
        for (i = 0; i < n; ++i) {
            ULONG src = (Globals.Head + i) % FEATHER_MAX_EVENTS;
            ULONG offset = i * sizeof(FEATHER_EVENT);
            if (offset + sizeof(FEATHER_EVENT) > OutputBufferLength) break;
            RtlCopyMemory((PUCHAR)OutputBuffer + offset, &Globals.Events[src],
                          sizeof(FEATHER_EVENT));
        }
        *ReturnLength = i * sizeof(FEATHER_EVENT);
        KeReleaseSpinLock(&Globals.Lock, oldIrql);
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
}

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, FeatherPreCreate, NULL },
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
