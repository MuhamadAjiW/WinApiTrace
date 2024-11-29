// WinApiTrace.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <misc.h>
#include <traceapi/traceapi.cpp>

DWORD main(int argc, char** argv)
{
    something();

    (void)argc;
    (void)argv;

    printf("testapi: Starting\n");
    ProcessAttach(NULL);
    Sleep(100);
    ProcessDetach(NULL);

    return 0;
}
