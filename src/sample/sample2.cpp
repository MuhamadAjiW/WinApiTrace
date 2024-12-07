// sample2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <winternl.h>
#include <iostream>

// ---Function headers---
NTSTATUS(__stdcall* ext_NtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions);

NTSTATUS(__stdcall* ext_NtWriteFile)(
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

NTSTATUS(__stdcall* ext_NtOpenEvent)(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS(__stdcall* ext_NtSetEvent)(
    HANDLE EventHandle,
    PLONG PreviousState);

VOID(__stdcall* ext_RtlInitUnicodeString)(
    PUNICODE_STRING         DestinationString,
    __drv_aliasesMem PCWSTR SourceString);

#define PIPE_NAME L"\\Device\\NamedPipe\\ipc_pipe"
#define EVENT_NAME L"\\BaseNamedObjects\\ipc_event"
#define FILE_PIPE_MESSAGE_TYPE 0x00000001
#define FILE_PIPE_MESSAGE_MODE 0x00000001
#define FILE_PIPE_QUEUE_OPERATION 0x00000000

// NTSTATUS information codes
// Guide on the numbers: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

VOID attachNT(PVOID* ppvReal, const CHAR* psz, const WCHAR* lib)
{
    HMODULE hNtdll = LoadLibrary(lib);
    *ppvReal = (PVOID)GetProcAddress(hNtdll, psz);
}

int main() {
    std::cout << "Initializing libraries..." << std::endl;

    attachNT(&(PVOID&)ext_NtOpenFile, "NtOpenFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtWriteFile, "NtWriteFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtClose, "NtClose", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtOpenEvent, "NtOpenEvent", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtSetEvent, "NtSetEvent", L"ntdll.dll");
    attachNT(&(PVOID&)ext_RtlInitUnicodeString, "RtlInitUnicodeString", L"ntdll.dll");

    std::cout << "Initializing libraries [Success]..." << std::endl;
    std::cout << "Initializing attributes..." << std::endl;

    NTSTATUS status = { 0 };
    HANDLE hEvent = { 0 };
    IO_STATUS_BLOCK ioStatusBlock = { 0 };

    // Open the communication pipe
    HANDLE hPipe = { 0 };
    UNICODE_STRING pipeName = { 0 };
    OBJECT_ATTRIBUTES objAttr = { 0 };

    ext_RtlInitUnicodeString(&pipeName, PIPE_NAME);
    InitializeObjectAttributes(
        &objAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );


    std::cout << "Initializing attributes [Success]..." << std::endl;
    std::cout << "Initializing pipes..." << std::endl;

    // Open named pipe
    status = ext_NtOpenFile(
        &hPipe,
        GENERIC_READ | GENERIC_WRITE,
        &objAttr,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        0
    );

    std::cout << "------------------------" << std::endl;
    std::cout << "Pipename: "; std::wcout << pipeName.Buffer << std::endl;
    std::cout << "Status block info: " << ioStatusBlock.Information << std::endl;
    std::cout << "NtOpenFile Code: 0x" << std::hex << status << std::endl;
    if (status < 0) {
        std::cout << "Failed to open named pipe. " << std::endl;
        return 1;
    }
    std::cout << "------------------------" << std::endl;
    std::cout << "Initializing pipes [Success]..." << std::endl;

    std::cout << "Initializing event..." << std::endl;

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

    status = ext_NtOpenEvent(
        &hEvent,
        EVENT_ALL_ACCESS,
        &eventAttr
    );

    std::cout << "------------------------" << std::endl;
    std::cout << "Eventname: "; std::wcout << eventName.Buffer << std::endl;
    std::cout << "NtOpenEvent Code: 0x" << std::hex << status << std::endl;
    if (status < 0) {
        std::cout << "Failed to open event. " << std::endl;
        return 1;
    }
    std::cout << "------------------------" << std::endl;
    std::cout << "Initializing event [Success]..." << std::endl;

    std::cout << "Sending message to server..." << std::endl;

    char buffer[512] = { 0 };
    const char* message = "Hello World! [Hi!]";
    ioStatusBlock = { 0 };
    status = ext_NtWriteFile(
        hPipe,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        (void*)message,
        strlen(message) + 1,
        NULL,
        NULL
    );

    std::cout << "------------------------" << std::endl;
    std::cout << "Status block info: " << std::dec << ioStatusBlock.Information << std::endl;
    std::cout << "NtWriteFile Code: 0x" << std::hex << status << std::endl;

    if (status != 0) {
        std::cerr << "Failed to send message: " << std::endl;
        return 1;
    }
    std::cout << "------------------------" << std::endl;
    std::cout << "Sending message to server [Success]..." << std::endl;
    std::cout << "Sending event to server..." << std::endl;

    status = ext_NtSetEvent(
        hEvent,
        NULL
    );
    std::cout << "NtSetEvent Code: 0x" << std::hex << status << std::endl;
    std::cout << "------------------------" << std::endl;
    std::cout << "Sending event to server [Success]..." << std::endl;

    std::cout << "Closing pipe..." << std::endl;

    status = ext_NtClose(hPipe);

    std::cout << "------------------------" << std::endl;
    std::cout << "NtClose Code: 0x" << std::hex << status << std::endl;
    std::cout << "------------------------" << std::endl;
    std::cout << "Closing pipe [Success]..." << std::endl;

    std::cout << "Program finished" << std::endl;

    return 0;
}