// Sample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <synchapi.h>

int main()
{
    const WCHAR* filePath = L"testfile.txt";
    int count = 0;

    Sleep(4200);
    while (count < 6) {
        // Call CreateFile, which internally calls NtCreateFile
        HANDLE hFile = CreateFile(
            filePath,                     // File name
            GENERIC_WRITE,                // Desired access
            0,                            // Share mode
            NULL,                         // Security attributes
            CREATE_ALWAYS,                // Creation disposition
            FILE_ATTRIBUTE_NORMAL,        // Flags and attributes
            NULL                          // Template file
        );

        std::cout << "File created: " << count << std::endl;
        const char* data = "Hello, world!";
        DWORD written;
        WriteFile(hFile, data, strlen(data), &written, NULL);
        CloseHandle(hFile);

        count++;
        Sleep(1000);
    }

    return 0;
}
