#pragma once

#include <windef.h>
#include <winternl.h>

typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
        ULONG CallbackId; // only valid for LPC_REQUEST messages
    };
} PORT_MESSAGE, *PPORT_MESSAGE;

enum LPC_MESSAGE_TYPES
{
    LPC_INIT,
    LPC_REQUEST,
    LPC_REPLY,
    LPC_DATAGRAM,
    LPC_LOST_REPLY,
    LPC_PORT_CLOSED,
    LPC_CLIENT_DIED,
    LPC_EXCEPTION,
    LPC_DEBUG_EVENT,
    LPC_ERROR_EVENT,
    LPC_CONNECTION_REQUEST,
    LPC_CONNECTION_REPLY,
    LPC_CANCELED,
    LPC_UNREGISTER_PROCESS
};

constexpr unsigned LPC_MESSAGE_TYPE = 0xff;

enum ALPC_MSGFLGS
{
    ALPC_MSGFLG_REPLY_MESSAGE = 1,
    ALPC_MSGFLG_LPC_MODE = 2,
    ALPC_MSGFLG_RELEASE_MESSAGE = 0x10000,
    ALPC_MSGFLG_SYNC_REQUEST = 0x20000,
    ALPC_MSGFLG_WAIT_USER_MODE = 0x100000,
    ALPC_MSGFLG_WAIT_ALERTABLE = 0x200000,
    ALPC_MSGFLG_WOW64_CALL = 0x80000000
};

enum ALPC_MESSAGE_ATTRIBUTE_FLAGS
{
    ALPC_MESSAGE_HANDLE_ATTRIBUTE = 0x10000000,
    ALPC_MESSAGE_CONTEXT_ATTRIBUTE = 0x20000000,
    ALPC_MESSAGE_VIEW_ATTRIBUTE = 0x40000000,
    ALPC_MESSAGE_SECURITY_ATTRIBUTE = 0x80000000    
};

enum ALPC_PORT_INFORMATION_CLASS
{
    AlpcBasicInformation,
    AlpcPortInformation,
    AlpcAssociateCompletionPortInformation,
    AlpcConnectedSIDInformation,
    AlpcServerInformation,
    AlpcMessageZoneInformation,
    AlpcRegisterCompletionListInformation,
    AlpcUnregisterCompletionListInformation,
    AlpcAdjustCompletionListConcurrencyCountInformation,
    AlpcRegisterCallbackInformation,
    AlpcCompletionListRundownInformation,
    AlpcWaitForPortReferences,
    AlpcServerSessionInformation
};

typedef struct _ALPC_PORT_ATTRIBUTES
{
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_COMPLETION_LIST_STATE
{
    union
    {
        struct
        {
            ULONG64 Head : 24;
            ULONG64 Tail : 24;
            ULONG64 ActiveThreadCount : 16;
        } s1;
        ULONG64 Value;
    } u1;
} ALPC_COMPLETION_LIST_STATE, * PALPC_COMPLETION_LIST_STATE;

typedef struct DECLSPEC_ALIGN(128) _ALPC_COMPLETION_LIST_HEADER
{
    ULONG64 StartMagic;

    ULONG TotalSize;
    ULONG ListOffset;
    ULONG ListSize;
    ULONG BitmapOffset;
    ULONG BitmapSize;
    ULONG DataOffset;
    ULONG DataSize;
    ULONG AttributeFlags;
    ULONG AttributeSize;

    DECLSPEC_ALIGN(128) ALPC_COMPLETION_LIST_STATE State;
    ULONG LastMessageId;
    ULONG LastCallbackId;
    DECLSPEC_ALIGN(128) ULONG PostCount;
    DECLSPEC_ALIGN(128) ULONG ReturnCount;
    DECLSPEC_ALIGN(128) ULONG LogSequenceNumber;
    DECLSPEC_ALIGN(128) RTL_SRWLOCK UserLock;

    ULONG64 EndMagic;
} ALPC_COMPLETION_LIST_HEADER, *PALPC_COMPLETION_LIST_HEADER;

struct AlpcPortAssociateCompletionPort
{
    PVOID CompletionKey;
    HANDLE CompletionPort;
};

typedef NTSTATUS(NTAPI* NtAlpcCreatePort_t)(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes);

typedef VOID(NTAPI* RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

typedef NTSTATUS(NTAPI* NtAlpcSendWaitReceivePort_t)(HANDLE PortHandle, ULONG Flags, PPORT_MESSAGE SendMsg, PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    PPORT_MESSAGE ReceiveMessage, PSIZE_T BufferLength, PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes, PLARGE_INTEGER Timeout);
    
typedef NTSTATUS(NTAPI* NtAlpcAcceptConnectPort_t)(PHANDLE ConnectionPortHandle, HANDLE PortHandle, ULONG Flags, POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES PortAttributes, PVOID PortContext, PPORT_MESSAGE ConnectionRequest, PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
    BOOLEAN AcceptConnection);
    
typedef NTSTATUS(NTAPI* AlpcInitializeMessageAttribute_t)(ULONG AttributeFlags, PALPC_MESSAGE_ATTRIBUTES Buffer, ULONG BufferSize, PSIZE_T RequiredBufferSize);

typedef PVOID(NTAPI* AlpcGetMessageAttribute_t)(PALPC_MESSAGE_ATTRIBUTES Buffer, ULONG AttributeFlag);

typedef NTSTATUS(NTAPI* NtAlpcConnectPort_t)(PHANDLE PortHandle, PUNICODE_STRING PortName, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes,
    ULONG Flags, PSID RequiredServerSid, PPORT_MESSAGE ConnectionMessage, PULONG BufferLength, PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    PALPC_MESSAGE_ATTRIBUTES InMessageAttributes, PLARGE_INTEGER Timeout);
    
typedef ULONG (NTAPI* RtlNtStatusToDosError_t)(NTSTATUS Status);

typedef NTSTATUS (NTAPI* AlpcRegisterCompletionList_t)(HANDLE PortHandle, PALPC_COMPLETION_LIST_HEADER Buffer, ULONG Size, ULONG ConcurrencyCount, ULONG AttributeFlags);

typedef NTSTATUS (NTAPI* NtAlpcSetInformation_t)(HANDLE PortHandle, ALPC_PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length);

typedef NTSTATUS (NTAPI* NtAlpcCancelMessage_t)(HANDLE PortHandle, ULONG Flags, PVOID MessageContext);
