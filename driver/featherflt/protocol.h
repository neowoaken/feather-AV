#ifndef FEATHER_PROTOCOL_H
#define FEATHER_PROTOCOL_H

/*
 * Shared kernel/user protocol for the Feather AV on-access minifilter.
 *
 * Include Windows headers first (fltKernel.h in the driver, windows.h +
 * fltuser.h in user mode). This header deliberately has no includes so it can
 * be compiled by both the WDK C compiler and the MSVC C++ compiler.
 *
 * Wire format:
 *   kernel -> user : FEATHER_SCAN_REQUEST   (raw body, no header)
 *   user -> kernel : FEATHER_SCAN_REPLY     (raw body, no header)
 *
 * FilterGetMessage / FilterReplyMessage add FILTER_MESSAGE_HEADER and
 * FILTER_REPLY_HEADER in user mode; FltSendMessage strips them in kernel mode.
 */

#define FEATHER_PORT_NAME      L"\\FeatherFltPort"
#define FEATHER_PATH_MAX       520       // WCHARs, including the terminator
#define FEATHER_PROTOCOL_VERSION 4

// Values returned in FEATHER_SCAN_REPLY.Verdict.
#define FEATHER_VERDICT_ALLOW      0
#define FEATHER_VERDICT_BLOCK      1
#define FEATHER_VERDICT_QUARANTINE 2

// Flags in FEATHER_SCAN_REPLY.Flags.
#define FEATHER_REPLY_FLAG_CACHED   0x00000001u
#define FEATHER_REPLY_FLAG_DEGRADED 0x00000002u

// User-mode control messages sent to the filter's message callback.
#define FEATHER_MSG_STATUS     1
#define FEATHER_MSG_EVENTS     2
#define FEATHER_MSG_CLEAR      3

typedef struct _FEATHER_SCAN_REQUEST {
    ULONG64 MessageId;          // copied from FILTER_MESSAGE_HEADER by user mode
    ULONG ProcessId;            // process that attempted the open
    ULONG PathLength;           // bytes of Path in use (excluding terminator)
    ACCESS_MASK DesiredAccess;  // original IRP_MJ_CREATE desired access
    WCHAR Path[FEATHER_PATH_MAX];
} FEATHER_SCAN_REQUEST, *PFEATHER_SCAN_REQUEST;

typedef struct _FEATHER_SCAN_REPLY {
    ULONG Verdict;
    ULONG Flags;
} FEATHER_SCAN_REPLY, *PFEATHER_SCAN_REPLY;

typedef struct _FEATHER_EVENT {
    ULONG64 MessageId;
    ULONG ProcessId;
    ULONG PathLength;
    ULONG Verdict;
    WCHAR Path[FEATHER_PATH_MAX];
} FEATHER_EVENT, *PFEATHER_EVENT;

typedef struct _FEATHER_STATUS {
    ULONG Loaded;
    ULONG Version;
    ULONG EventCount;
    ULONG Dropped;
    ULONG ServiceConnected;
    ULONG Timeouts;
} FEATHER_STATUS, *PFEATHER_STATUS;

#endif /* FEATHER_PROTOCOL_H */
