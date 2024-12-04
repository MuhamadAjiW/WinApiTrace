
#include <iostream>

#include <windows.h>
#include <wincrypt.h>
#include <security.h>
#include <stdio.h>
#include <winternl.h>
#include <shlobj.h>
#include <detours/detours.h>

// --Real-Functions-Not-Needed-for-Model--
NTSTATUS(__stdcall* Real_NtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    CONST VOID* BaseAddress,
    ULONG MemoryInformationClass,
    VOID* MemoryInformation,
    SIZE_T MemoryInformationLength,
    SIZE_T* ReturnLength);

NTSTATUS(__stdcall* Real_NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesReaded);

NTSTATUS(__stdcall* Real_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    VOID* ProcessInformation,
    ULONG ProcessInformationLength,
    ULONG* ReturnLength);

NTSTATUS(__stdcall* Real_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    VOID* ThreadInformation,
    ULONG ThreadInformationLength,
    ULONG* ReturnLength);

NTSTATUS(__stdcall* Real_NtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    VOID* ObjectInformation,
    ULONG ObjectInformationLength,
    ULONG* ReturnLength);

NTSTATUS(__stdcall* Real_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    HANDLE* TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options);

NTSTATUS(__stdcall* Real_NtFsControlFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    const void* InputBuffer,
    ULONG InputBufferLength,
    void* OutputBuffer,
    ULONG OutputBufferLength);

NTSTATUS(__stdcall* Real_NtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS(__stdcall* Real_NtClose)(
    HANDLE Handle);

NTSTATUS(__stdcall* Real_NtDelayExecution)(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval);

NTSTATUS(__stdcall* Real_NtWaitForSingleObject)(
    HANDLE Object,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

NTSTATUS(__stdcall* Real_NtOpenThread)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId);

NTSTATUS(__stdcall* Real_NtResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount);

NTSTATUS(__stdcall* Real_LdrRegisterDllNotification)(
    ULONG Flags,
    LDR_DLL_NOTIFICATION_FUNCTION LdrDllNotificationFunction,
    VOID* Context, VOID** Cookie);

// Hooked-Functions-Not-Needed-for-Model--
NTSTATUS Mine_NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    CONST VOID* BaseAddress,
    ULONG MemoryInformationClass,
    VOID* MemoryInformation,
    SIZE_T MemoryInformationLength,
    SIZE_T* ReturnLength)
{
    LOG_HOOK(
        NtQueryVirtualMemory,
        "ppLpLp",
        ProcessHandle,
        BaseAddress,
        MemoryInformationClass,
        MemoryInformation,
        MemoryInformationLength,
        ReturnLength
    );
}

NTSTATUS Mine_NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesReaded)
{
    LOG_HOOK(
        NtReadVirtualMemory,
        "pppLp",
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToRead,
        NumberOfBytesReaded
    );
}

NTSTATUS Mine_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    VOID* ProcessInformation,
    ULONG ProcessInformationLength,
    ULONG* ReturnLength)
{
    LOG_HOOK(
        NtQueryInformationProcess,
        "pLpLp",
        ProcessHandle,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationLength,
        ReturnLength
    );
}

NTSTATUS Mine_NtQueryInformationThread(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    VOID* ThreadInformation,
    ULONG ThreadInformationLength,
    ULONG* ReturnLength)
{
    LOG_HOOK(
        NtQueryInformationThread,
        "pLpLp",
        ThreadHandle,
        ThreadInformationClass,
        ThreadInformation,
        ThreadInformationLength,
        ReturnLength
    );
}

NTSTATUS Mine_NtQueryObject(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    VOID* ObjectInformation,
    ULONG ObjectInformationLength,
    ULONG* ReturnLength)
{
    LOG_HOOK(
        NtQueryObject,
        "pLpLp",
        Handle,
        ObjectInformationClass,
        ObjectInformation,
        ObjectInformationLength,
        ReturnLength
    );
}

NTSTATUS Mine_NtDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    HANDLE* TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options)
{
    LOG_HOOK(
        NtDuplicateObject,
        "ppppLLL",
        SourceProcessHandle,
        SourceHandle,
        TargetProcessHandle,
        TargetHandle,
        DesiredAccess,
        HandleAttributes,
        Options
    );
}

NTSTATUS Mine_NtFsControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    const void* InputBuffer,
    ULONG InputBufferLength,
    void* OutputBuffer,
    ULONG OutputBufferLength)
{
    LOG_HOOK(
        NtFsControlFile,
        "pppppLpLpL",
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FsControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength
    );
}

NTSTATUS Mine_NtSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass)
{
    LOG_HOOK(
        NtSetInformationFile,
        "pppLp",
        FileHandle,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass
    );
}

NTSTATUS Mine_NtClose(
    HANDLE Handle)
{
    LOG_HOOK(
        NtClose,
        "p",
        Handle
    );
}

NTSTATUS Mine_NtDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval)
{
    LOG_HOOK(
        NtDelayExecution,
        "dp",
        Alertable,
        DelayInterval
    );
}

NTSTATUS Mine_NtWaitForSingleObject(
    HANDLE Object,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout)
{
    LOG_HOOK(
        NtWaitForSingleObject,
        "pdp",
        Object,
        Alertable,
        Timeout
    );
}

NTSTATUS Mine_NtOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId)
{
    LOG_HOOK(
        NtOpenThread,
        "pLpp",
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
}

NTSTATUS Mine_NtResumeThread(
    HANDLE ThreadHandle,
    PULONG SuspendCount)
{
    LOG_HOOK(
        NtResumeThread,
        "pp",
        ThreadHandle,
        SuspendCount
    );
}

NTSTATUS Mine_LdrRegisterDllNotification(
    ULONG Flags,
    LDR_DLL_NOTIFICATION_FUNCTION LdrDllNotificationFunction,
    VOID* Context,
    VOID** Cookie)
{
    LOG_HOOK(
        LdrRegisterDllNotification,
        "Lppp",
        Flags,
        LdrDllNotificationFunction,
        Context,
        Cookie
    );
}
