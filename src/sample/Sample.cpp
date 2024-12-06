// Sample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

//#include <iostream>
//#include <windows.h>
//#include <synchapi.h>
//
//int main()
//{
//    const WCHAR* filePath = L"testfile.txt";
//
//    // Call CreateFile, which internally calls NtCreateFile
//    HANDLE hFile = CreateFile(
//        filePath,                    // File name
//        GENERIC_WRITE,                // Desired access
//        0,                            // Share mode
//        NULL,                         // Security attributes
//        CREATE_ALWAYS,                // Creation disposition
//        FILE_ATTRIBUTE_NORMAL,        // Flags and attributes
//        NULL                          // Template file
//    );
//
//    if (hFile == INVALID_HANDLE_VALUE) {
//        std::cerr << "Failed to create file. Error: " << GetLastError() << std::endl;
//    }
//    else {
//        std::cout << "File created successfully." << std::endl;
//        // Optionally, write to the file
//        const char* data = "Hello, world!";
//        DWORD written;
//        WriteFile(hFile, data, strlen(data), &written, NULL);
//        std::cout << "Data written to the file." << std::endl;
//        CloseHandle(hFile);
//    }
//
//    return 0;
//}

// #include <iostream>
// #include <windows.h>
// using namespace std;

// int main(int argc, const char** argv)
// {
//     wcout << "Creating an instance of a named pipe..." << endl;

//     // Create a pipe to send data
//     HANDLE pipe = CreateNamedPipe(
//         L"\\\\.\\pipe\\my_pipe", // name of the pipe
//         PIPE_ACCESS_OUTBOUND, // 1-way pipe -- send only
//         PIPE_TYPE_BYTE, // send data as a byte stream
//         1, // only allow 1 instance of this pipe
//         0, // no outbound buffer
//         0, // no inbound buffer
//         0, // use default wait time
//         NULL // use default security attributes
//     );

//     if (pipe == NULL || pipe == INVALID_HANDLE_VALUE) {
//         wcout << "Failed to create outbound pipe instance.";
//         // look up error code here using GetLastError()
//         system("pause");
//         return 1;
//     }

//     wcout << "Waiting for a client to connect to the pipe..." << endl;

//     // This call blocks until a client process connects to the pipe
//     BOOL result = ConnectNamedPipe(pipe, NULL);
//     if (!result) {
//         wcout << "Failed to make connection on named pipe." << endl;
//         // look up error code here using GetLastError()
//         CloseHandle(pipe); // close the pipe
//         return 1;
//     }

//     wcout << "Sending data to pipe..." << endl;

//     // This call blocks until a client process reads all the data
//     const wchar_t* data = L"*** Hello Pipe World ***";
//     DWORD numBytesWritten = 0;
//     result = WriteFile(
//         pipe, // handle to our outbound pipe
//         data, // data to send
//         wcslen(data) * sizeof(wchar_t), // length of data to send (bytes)
//         &numBytesWritten, // will store actual amount of data sent
//         NULL // not using overlapped IO
//     );

//     if (result) {
//         wcout << "Number of bytes sent: " << numBytesWritten << endl;
//     }
//     else {
//         wcout << "Failed to send data." << endl;
//         // look up error code here using GetLastError()
//     }

//     // Close the pipe (automatically disconnects client too)
//     CloseHandle(pipe);

//     wcout << "Done." << endl;

//     return 0;
// }

#include <windows.h>
#include <winternl.h>
#include <iostream>

// ---Function headers---
NTSTATUS(__stdcall* ext_NtCreateNamedPipeFile)(
    PHANDLE            FileHandle,
    ULONG              DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    ULONG              NamedPipeType,
    ULONG              ReadMode,
    ULONG              CompletionMode,
    ULONG              MaximumInstances,
    ULONG              InboundQuota,
    ULONG              OutboundQuota,
    PLARGE_INTEGER     DefaultTimeout);

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

#define PIPE_NAME L"\\Device\\NamedPipe\\my_pipe"
#define FILE_PIPE_BYTE_STREAM_TYPE 0x00000000
#define FILE_PIPE_BYTE_STREAM_MODE 0x00000000
#define FILE_PIPE_COMPLETE_OPERATION 0x00000001
#define FILE_PIPE_MESSAGE_TYPE 0x00000001
#define FILE_PIPE_MESSAGE_MODE 0x00000001
#define FILE_PIPE_QUEUE_OPERATION 0x00000000

VOID attachNT(PVOID* ppvReal, const CHAR* psz, const WCHAR* lib)
{
    HMODULE hNtdll = LoadLibrary(lib);
    *ppvReal = (PVOID)GetProcAddress(hNtdll, psz);
}

int main() {
    std::cout << "Initializing libraries..." << std::endl;

    attachNT(&(PVOID&)ext_NtReadFile, "NtReadFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtWriteFile, "NtWriteFile", L"ntdll.dll");
    attachNT(&(PVOID&)ext_NtCreateNamedPipeFile, "NtCreateNamedPipeFile", L"ntdll.dll");
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

    // Create named pipe
    NTSTATUS status = ext_NtCreateNamedPipeFile(
        &hPipe,
        GENERIC_READ | GENERIC_WRITE,
        &objAttr,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        0,
        FILE_PIPE_MESSAGE_TYPE,
        FILE_PIPE_MESSAGE_MODE,
        FILE_PIPE_QUEUE_OPERATION,
        1,               // Maximum instances
        1024,            // Inbound quota
        1024,            // Outbound quota
        NULL             // Default timeout
    );

    if (status < 0) {
        std::cerr << "Failed to create named pipe. "
            << "Error Code: 0x" << std::hex << status << std::endl;

        switch (status) {
        case 0xC000000D:
            std::cerr << "Detailed: Invalid Parameter" << std::endl;
            break;
        case 0xC0000035:
            std::cerr << "Detailed: Pipe Not Available" << std::endl;
            break;
        default:
            std::cerr << "Unknown Error" << std::endl;
        }
        return 1;
    }

    std::cout << "Initializing pipes [Success]..." << std::endl;
    std::cout << "Waiting for client..." << std::endl;

    // Prepare status block and buffer
    IO_STATUS_BLOCK readStatusBlock = { 0 };
    char buffer[512] = { 0 };

    // Wait for client connection and read
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
        // Null terminate the received buffer
        buffer[readStatusBlock.Information] = '\0';
        std::cout << "Received: " << buffer << std::endl;

        // Prepare response
        IO_STATUS_BLOCK writeStatusBlock = { 0 };
        std::string response = "Message received";

        // Write response
        NTSTATUS writeStatus = ext_NtWriteFile(
            hPipe,
            NULL,
            NULL,
            NULL,
            &writeStatusBlock,
            (void*)response.c_str(),
            response.size(),
            NULL,
            NULL
        );

        if (writeStatus < 0) {
            std::cerr << "Failed to write response: " << std::hex << writeStatus << std::endl;
        }
    }
    else {
        std::cerr << "Failed to read from pipe: " << std::hex << readStatus << std::endl;
    }

    CloseHandle(hPipe);


    std::cout << "Program finished" << std::endl;

    return 0;
}