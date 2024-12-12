// Sample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <synchapi.h>

DWORD WINAPI sendThread(LPVOID lpParam) {
    const WCHAR* filePath = L"testfile.txt";
    int count = 0;

    Sleep(420);
    while (count < 500) {
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
        Sleep(20);
    }

    return 0;
}

#define thread_num 2

int main()
{
    HANDLE hFileThread[thread_num];
    DWORD dwFileThread[thread_num];

    for (size_t i = 0; i < thread_num; i++)
    {
        hFileThread[i] = CreateThread(
            NULL,
            0,
            sendThread,
            NULL,
            0,
            &dwFileThread[i]
        );
    }

    for (size_t i = 0; i < thread_num; i++)
    {
        WaitForSingleObject(hFileThread[i], INFINITE);
    }

    return 0;
}
