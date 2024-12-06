// sample2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// #include <iostream>
// #include <windows.h>
// using namespace std;

// int main(int argc, const char** argv)
// {
//     wcout << "Connecting to pipe..." << endl;

//     // Open the named pipe
//     // Most of these parameters aren't very relevant for pipes.
//     HANDLE pipe = CreateFile(
//         L"\\\\.\\pipe\\my_pipe",
//         GENERIC_READ, // only need read access
//         FILE_SHARE_READ | FILE_SHARE_WRITE,
//         NULL,
//         OPEN_EXISTING,
//         FILE_ATTRIBUTE_NORMAL,
//         NULL
//     );

//     if (pipe == INVALID_HANDLE_VALUE) {
//         wcout << "Failed to connect to pipe." << endl;
//         // look up error code here using GetLastError()
//         return 1;
//     }

//     wcout << "Reading data from pipe..." << endl;

//     // The read operation will block until there is data to read
//     wchar_t buffer[128];
//     DWORD numBytesRead = 0;
//     BOOL result = ReadFile(
//         pipe,
//         buffer, // the data from the pipe will be put here
//         127 * sizeof(wchar_t), // number of bytes allocated
//         &numBytesRead, // this will store number of bytes actually read
//         NULL // not using overlapped IOp
//     );

//     if (result) {
//         buffer[numBytesRead / sizeof(wchar_t)] = '\0'; // null terminate the string
//         wcout << "Number of bytes read: " << numBytesRead << endl;
//         wcout << "Message: " << buffer << endl;
//     }
//     else {
//         wcout << "Failed to read data from the pipe." << endl;
//     }

//     // Close our pipe handle
//     CloseHandle(pipe);

//     wcout << "Done." << endl;

//     return 0;
// }

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

VOID(__stdcall* ext_RtlInitUnicodeString)(
    PUNICODE_STRING         DestinationString,
    __drv_aliasesMem PCWSTR SourceString
    );

#define PIPE_NAME L"\\.\\pipe\\WinAPiTraceIPC"

VOID attachNT(PVOID* ppvReal, const CHAR* psz, const WCHAR* lib)
{
    HMODULE hNtdll = LoadLibrary(lib);
    *ppvReal = (PVOID)GetProcAddress(hNtdll, psz);
}

int main() {
    std::cout << "Initializing libraries..." << std::endl;

    attachNT(&(PVOID&)ext_NtOpenFile, "NtOpenFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtReadFile, "NtReadFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtWriteFile, "NtWriteFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_RtlInitUnicodeString, "RtlInitUnicodeString", L"ntdll.dll");

    std::cout << "Initializing libraries [Success]..." << std::endl;
    std::cout << "Initializing attributes..." << std::endl;

    HANDLE hPipe;
    UNICODE_STRING pipeName;
    ext_RtlInitUnicodeString(&pipeName, PIPE_NAME);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &pipeName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK ioStatusBlock = { 0 };

    std::cout << "Initializing attributes [Success]..." << std::endl;
    std::cout << "Initializing pipes..." << std::endl;

    // Open named pipe
    NTSTATUS status = ext_NtOpenFile(
        &hPipe,
        GENERIC_READ | GENERIC_WRITE,
        &objAttr,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN
    );

    if (status >= 0) {
        std::cout << "Initializing pipes [Success]..." << std::endl;
        std::cout << "Connecting to server..." << std::endl;

        char buffer[512] = { 0 };
        std::string message = "Hello World! [Hi!]";

        // Ensure status blocks are zeroed out
        IO_STATUS_BLOCK writeStatusBlock = { 0 };
        IO_STATUS_BLOCK readStatusBlock = { 0 };

        NTSTATUS writeStatus = ext_NtWriteFile(
            hPipe,
            NULL,
            NULL,
            NULL,
            &writeStatusBlock,
            (void*)message.c_str(),
            message.size(),
            NULL,
            NULL
        );

        if (writeStatus >= 0) {
            std::cout << "Message sent successfully." << std::endl;

            NTSTATUS readStatus = ext_NtReadFile(
                hPipe,
                NULL,
                NULL,
                NULL,
                &readStatusBlock,
                buffer,
                sizeof(buffer) - 1,  // Leave room for null terminator
                NULL,
                NULL
            );

            if (readStatus >= 0) {
                buffer[readStatusBlock.Information] = '\0';  // Null terminate
                std::cout << "Server response: " << buffer << std::endl;
            }
            else {
                std::cerr << "Failed to read response: " << std::hex << readStatus << std::endl;
            }
        }
        else {
            std::cerr << "Failed to send message: " << std::hex << writeStatus << std::endl;
        }

        CloseHandle(hPipe);
    }
    else {
        std::cerr << "Failed to open named pipe: " << std::hex << status << std::endl;
    }

    std::cout << "Program finished" << std::endl;

    return 0;
}