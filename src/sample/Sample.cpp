// Sample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <winternl.h>
#include <iostream>

// ---Structs---
typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE, * PEVENT_TYPE;

// ---Function headers---
NTSTATUS(__stdcall* ext_NtCreateNamedPipeFile)(
    PHANDLE FileHandle,
    ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    ULONG NamedPipeType,
    ULONG ReadMode,
    ULONG CompletionMode,
    ULONG MaximumInstances,
    ULONG InboundQuota,
    ULONG OutboundQuota,
    PLARGE_INTEGER DefaultTimeout);

NTSTATUS(__stdcall* ext_NtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key);

NTSTATUS(__stdcall* ext_NtClose)(
    HANDLE Handle);

NTSTATUS(__stdcall* ext_NtFsControlFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength);

NTSTATUS(__stdcall* ext_NtWaitForSingleObject)(
    HANDLE Object,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

NTSTATUS(__stdcall* ext_NtCreateEvent)(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    EVENT_TYPE EventType,
    BOOLEAN InitialState);

VOID(__stdcall* ext_RtlInitUnicodeString)(
    PUNICODE_STRING         DestinationString,
    __drv_aliasesMem PCWSTR SourceString
    );

#define PIPE_NAME L"\\Device\\NamedPipe\\ipc_pipe"
#define EVENT_NAME L"\\BaseNamedObjects\\ipc_event"
#define FILE_PIPE_MESSAGE_TYPE 0x00000001
#define FILE_PIPE_MESSAGE_MODE 0x00000001
#define FILE_PIPE_QUEUE_OPERATION 0x00000000

// FSCTL codes https://processhacker.sourceforge.io/doc/ntioapi_8h.html

// IO_STATUS_BLOCK Information codes:
// FILE_SUPERSEDED = 0;
// FILE_OPENED = 1;
// FILE_CREATED = 2;
// FILE_OVERWRITTEN = 3;
// FILE_EXISTS = 4;
// FILE_DOES_NOT_EXIST = 5
// No info = 99999

// NTSTATUS information codes
// Guide on the numbers: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

VOID attachNT(PVOID* ppvReal, const CHAR* psz, const WCHAR* lib)
{
    HMODULE hNtdll = LoadLibrary(lib);
    *ppvReal = (PVOID)GetProcAddress(hNtdll, psz);
}

int main() {
    std::cout << "Initializing libraries..." << std::endl;

    attachNT(&(PVOID&)ext_NtCreateNamedPipeFile, "NtCreateNamedPipeFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtReadFile, "NtReadFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtClose, "NtClose", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtFsControlFile, "NtFsControlFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtWaitForSingleObject, "NtWaitForSingleObject", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtCreateEvent, "NtCreateEvent", L"ntdll.dll");
    attachNT(&(PVOID&)ext_RtlInitUnicodeString, "RtlInitUnicodeString", L"ntdll.dll");

    std::cout << "Initializing libraries [Success]..." << std::endl;
    std::cout << "Initializing attributes..." << std::endl;

    NTSTATUS status = { 0 };
    HANDLE hEvent = { 0 };
    IO_STATUS_BLOCK ioStatusBlock = { 0 };

    // Create the communication pipe
    HANDLE hPipe = { 0 };
    UNICODE_STRING pipeName = { 0 };
    OBJECT_ATTRIBUTES pipeAttr = { 0 };
    LARGE_INTEGER pipeTimeout = { 0 };

    ioStatusBlock.Information = 99999;
    ext_RtlInitUnicodeString(&pipeName, PIPE_NAME);
    InitializeObjectAttributes(
        &pipeAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    pipeTimeout.QuadPart = -900000000LL;

    std::cout << "Initializing attributes [Success]..." << std::endl;
    std::cout << "Initializing pipes..." << std::endl;

    status = ext_NtCreateNamedPipeFile(
        &hPipe,
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        &pipeAttr,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        0,
        FILE_PIPE_MESSAGE_TYPE,
        FILE_PIPE_MESSAGE_MODE,
        FILE_PIPE_QUEUE_OPERATION,
        1,
        1024,
        1024,
        &pipeTimeout
    );

    std::cout << "------------------------" << std::endl;
    std::cout << "Pipename: "; std::wcout << pipeName.Buffer << std::endl;
    std::cout << "Status block info: " << ioStatusBlock.Information << std::endl;
    std::cout << "NtCreateNamedPipeFile Code: 0x" << std::hex << status << std::endl;
    if (status < 0) {
        std::cout << "Failed to create named pipe. " << std::endl;
        return 1;
    }
    std::cout << "------------------------" << std::endl;
    std::cout << "Initializing pipes [Success]..." << std::endl;
    std::cout << "Waiting for client..." << std::endl;

    // Wait for connection
    OBJECT_ATTRIBUTES eventAttr = { 0 };
    UNICODE_STRING eventName = { 0 };
    ext_RtlInitUnicodeString(&eventName, EVENT_NAME);
    InitializeObjectAttributes(
        &eventAttr,
        &eventName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ext_NtCreateEvent(
        &hEvent,
        EVENT_ALL_ACCESS,
        &eventAttr,
        SynchronizationEvent,
        FALSE
    );
    std::cout << "------------------------" << std::endl;
    std::cout << "Eventname: "; std::wcout << eventName.Buffer << std::endl;
    std::cout << "NtCreateEvent Code: 0x" << std::hex << status << std::endl;

    status = ext_NtWaitForSingleObject(hEvent, TRUE, NULL);

    std::cout << "------------------------" << std::endl;
    std::cout << "NtWaitForSingleObject Code: 0x" << std::hex << status << std::endl;
    std::cout << "------------------------" << std::endl;
    std::cout << "Waiting for client [Success]..." << std::endl;
    std::cout << "Reading from pipes..." << std::endl;

    // Read from the pipe
    ioStatusBlock = { 0 };
    ioStatusBlock.Information = 99999;
    char buffer[512] = { 0 };

    status = ext_NtReadFile(
        hPipe,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        buffer,
        sizeof(buffer) - 1,  // Leave room for null terminator
        NULL,
        NULL
    );

    std::cout << "------------------------" << std::endl;
    std::cout << "NtReadFile Code: 0x" << std::hex << status << std::endl;
    std::cout << "Status block info: " << std::dec << ioStatusBlock.Information << std::endl;
    std::cout << "------------------------" << std::endl;

    if (ioStatusBlock.Information < 512) {
        buffer[ioStatusBlock.Information] = '\0';
        std::cout << "Received: " << buffer << std::endl;
    }
    else {
        std::cout << "Message too large or invalid" << std::endl;
    }
    std::cout << "Reading from pipes [Success]..." << std::endl;
    std::cout << "Closing pipe..." << std::endl;

    ext_NtClose(hPipe);

    std::cout << "------------------------" << std::endl;
    std::cout << "NtClose Code: 0x" << std::hex << status << std::endl;
    std::cout << "------------------------" << std::endl;
    std::cout << "Closing pipe [Success]..." << std::endl;

    std::cout << "Program finished" << std::endl;

    return 0;
}