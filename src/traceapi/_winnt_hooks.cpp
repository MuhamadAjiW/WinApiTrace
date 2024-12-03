// _TODO: Work on hooking NT API's

#define SECURITY_WIN32

#include <iostream>

#include <windows.h>
#include <wincrypt.h>
#include <security.h>
#include <stdio.h>
#include <winternl.h>
#include <detours/detours.h>

#define LOG_HOOK(func_name, param_formats, ...) \
        std::chrono::high_resolution_clock::time_point call_time = std::chrono::high_resolution_clock::now(); \
        double relative_time = std::chrono::duration<double, std::milli>(call_time - start_time).count(); \
        LONG nThread = 0; \
        if (s_nTlsThread >= 0) { \
            nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread); \
        } \
        _PrintEnter("%lf;%ld;%s", relative_time, nThread, #func_name); \
        log_parameters_helper(param_formats, #__VA_ARGS__, __VA_ARGS__); \
        int rv = 0; \
        __try { \
            rv = Real_##func_name(__VA_ARGS__); \
        } \
        __finally { \
            _PrintExit("%s() -> %x\n", #func_name, rv); \
        }; \
        return rv;

void log_parameters_helper(
    const char* param_formats,
    const char* param_names,
    ...)
{
    const char* param = param_names;
    const char* format = param_formats;
    va_list args;
    va_start(args, param_names);

    while (param && *param) {
        const char* next_comma = strchr(param, ',');
        if (next_comma == NULL) next_comma = param + strlen(param);

        char name[256];
        snprintf(name, next_comma - param + (param == param_names), "%s", param + (param != param_names));

        switch (*format)
        {
        case 'd': // Integer
            _PrintEnter(";[%s]%d", name, va_arg(args, int));
            break;
        case 'l': // Long
            _PrintEnter(";[%s]%ld", name, va_arg(args, long));
            break;
        case 'D': // Unsigned integer
            _PrintEnter(";[%s]%u", name, va_arg(args, unsigned int));
            break;
        case 'L': // Unsigned long
            _PrintEnter(";[%s]%lu", name, va_arg(args, unsigned long));
            break;
        case 'f': // Float
            _PrintEnter(";[%s]%f", name, va_arg(args, float));
            break;
        case 'F': // Double
            _PrintEnter(";[%s]%lf", name, va_arg(args, double));
            break;
        case 'p': // Pointer
        default:
            _PrintEnter(";[%s]%p", name, va_arg(args, void*));
        }

        param = (*next_comma) ? next_comma + 1 : NULL;
        format++;
    }
    _PrintEnter("\n");

    va_end(args);
}

// --Structs--
typedef struct __CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} *PCLIENT_ID;

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3,
    KeyCachedInformation = 4,
    KeyFlagsInformation = 5,
    KeyVirtualizationInformation = 6,
    KeyHandleTagsInformation = 7,
    MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK LDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    const LDR_DLL_NOTIFICATION_DATA* NotificationData,
    VOID* Context);

// --Real-Functions--
NTSTATUS(__stdcall* Real_NtWriteFile)(HANDLE a0,
    HANDLE a1,
    PIO_APC_ROUTINE a2,
    PVOID a3,
    PIO_STATUS_BLOCK a4,
    PVOID a5,
    ULONG a6,
    PLARGE_INTEGER a7,
    PULONG a8);

NTSTATUS(__stdcall* Real_NtQueryVirtualMemory)(HANDLE ProcessHandle,
    CONST VOID* BaseAddress,
    ULONG MemoryInformationClass,
    VOID* MemoryInformation,
    SIZE_T MemoryInformationLength,
    SIZE_T* ReturnLength);

NTSTATUS(__stdcall* Real_NtAllocateVirtualMemory)(HANDLE ProcessHandle,
    VOID** BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T* RegionSize,
    ULONG AllocationType,
    ULONG Protect);

NTSTATUS(__stdcall* Real_NtFreeVirtualMemory)(HANDLE ProcessHandle,
    CONST VOID** BaseAddress,
    SIZE_T* RegionSize,
    ULONG FreeType);

NTSTATUS(__stdcall* Real_NtProtectVirtualMemory)(HANDLE ProcessHandle,
    CONST VOID** BaseAddress,
    SIZE_T* NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    ULONG* OldAccessProtection);

NTSTATUS(__stdcall* Real_NtReadVirtualMemory)(HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesReaded);

NTSTATUS(__stdcall* Real_NtQueryInformationProcess)(HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    VOID* ProcessInformation,
    ULONG ProcessInformationLength,
    ULONG* ReturnLength);

NTSTATUS(__stdcall* Real_NtQueryInformationThread)(HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    VOID* ThreadInformation,
    ULONG ThreadInformationLength,
    ULONG* ReturnLength);

NTSTATUS(__stdcall* Real_NtQueryObject)(HANDLE Handle,
    ULONG ObjectInformationClass,
    VOID* ObjectInformation,
    ULONG ObjectInformationLength,
    ULONG* ReturnLength);

NTSTATUS(__stdcall* Real_NtQueryKey)(HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

NTSTATUS(__stdcall* Real_NtDuplicateObject)(HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    HANDLE* TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options);

NTSTATUS(__stdcall* Real_NtFsControlFile)(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    const void* InputBuffer,
    ULONG InputBufferLength,
    void* OutputBuffer,
    ULONG OutputBufferLength);

NTSTATUS(__stdcall* Real_NtSetInformationFile)(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS(__stdcall* Real_NtClose)(HANDLE Handle);

NTSTATUS(__stdcall* Real_NtDelayExecution)(BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval);

NTSTATUS(__stdcall* Real_NtWaitForSingleObject)(HANDLE Object,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

NTSTATUS(__stdcall* Real_NtOpenThread)(PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId);

NTSTATUS(__stdcall* Real_NtResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount);

NTSTATUS(__stdcall* Real_LdrRegisterDllNotification)(ULONG Flags,
    LDR_DLL_NOTIFICATION_FUNCTION LdrDllNotificationFunction,
    VOID* Context, VOID** Cookie);

// --Hooked-Functions--
NTSTATUS WINAPI Mine_NtWriteFile(HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    LOG_HOOK(
        NtWriteFile,
        "ppppppLpp",
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key
    );
}

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

NTSTATUS Mine_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    VOID** BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T* RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    LOG_HOOK(
        NtAllocateVirtualMemory,
        "ppppLL",
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    );
}

NTSTATUS Mine_NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    CONST VOID** BaseAddress,
    SIZE_T* RegionSize,
    ULONG FreeType)
{
    LOG_HOOK(
        NtFreeVirtualMemory,
        "pppL",
        ProcessHandle,
        BaseAddress,
        RegionSize,
        FreeType
    );
}

NTSTATUS Mine_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    CONST VOID** BaseAddress,
    SIZE_T* NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    ULONG* OldAccessProtection)
{
    LOG_HOOK(
        NtProtectVirtualMemory,
        "pppLp",
        ProcessHandle,
        BaseAddress,
        NumberOfBytesToProtect,
        NewAccessProtection,
        OldAccessProtection
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

NTSTATUS Mine_NtQueryKey(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength)
{
    LOG_HOOK(
        NtQueryKey,
        "pppLp",
        KeyHandle,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength
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

//
///////////////////////////////////////////////////////////////// End of File.
