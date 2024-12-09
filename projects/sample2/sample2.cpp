// Sample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <synchapi.h>

int main()
{
    const WCHAR* filePath = L"testfile.txt";

    // Call CreateFile, which internally calls NtCreateFile
    HANDLE hFile = CreateFile(
        filePath,                    // File name
        GENERIC_WRITE,                // Desired access
        0,                            // Share mode
        NULL,                         // Security attributes
        CREATE_ALWAYS,                // Creation disposition
        FILE_ATTRIBUTE_NORMAL,        // Flags and attributes
        NULL                          // Template file
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create file. Error: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "File created successfully." << std::endl;
        // Optionally, write to the file
        const char* data = "Hello, world!";
        DWORD written;
        WriteFile(hFile, data, strlen(data), &written, NULL);
        std::cout << "Data written to the file." << std::endl;
        CloseHandle(hFile);
    }

    return 0;
}