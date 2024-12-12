// Sample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <synchapi.h>

LARGE_INTEGER timestamp_log_start, timestamp_log_end;
LARGE_INTEGER timer_freq;
double timer_period;

DWORD WINAPI sendThread(LPVOID lpParam)
{
    const WCHAR* filePath = L"testfile.txt";
    int count = 0;

    QueryPerformanceFrequency(&timer_freq);
    timer_period = (double)10000000 / timer_freq.QuadPart;

    QueryPerformanceCounter(&timestamp_log_start);

    LARGE_INTEGER timestamp_before, timestamp_after;
    long long total_duration = 0;

    Sleep(420);
    while (count < 500) {
        QueryPerformanceCounter(&timestamp_before);
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
        QueryPerformanceCounter(&timestamp_after);
        long long duration = (long long)((timestamp_after.QuadPart - timestamp_before.QuadPart) * timer_period);
        total_duration += duration;

        std::cout << "File created: " << count << std::endl;
        const char* data = "Hello, world!";
        DWORD written;
        WriteFile(hFile, data, strlen(data), &written, NULL);
        CloseHandle(hFile);

        count++;
        Sleep(20);
    }
    std::cout << "Call time: " << total_duration << std::endl;

    QueryPerformanceCounter(&timestamp_log_end);
    long long program_duration = (long long)((timestamp_log_end.QuadPart - timestamp_log_start.QuadPart) * timer_period);
    std::cout << "Total time: " << program_duration << std::endl;

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
