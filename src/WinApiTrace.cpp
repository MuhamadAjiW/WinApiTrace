// WinApiTrace.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <misc.h>
#include <traceapi/traceapi.cpp>

int main(int argc, char** argv)
{
    something();

    (void)argc;
    (void)argv;

    printf("testapi: Starting\n");
    ProcessAttach(NULL);
    Sleep(1000);
    Sleep(1000);
    ProcessDetach(NULL);
    printf("testapi: Program finished\n");

    return 0;
}
