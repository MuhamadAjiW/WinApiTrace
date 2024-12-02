// _TODO: Work on hooking NT API's

#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <winternl.h>
#include <detours/detours.h>

NTSTATUS(__stdcall*Real_NtWriteFile)(HANDLE a0,
    HANDLE a1,
    PIO_APC_ROUTINE a2,
    PVOID a3,
    PIO_STATUS_BLOCK a4,
    PVOID a5,
    ULONG a6,
    PLARGE_INTEGER a7,
    PULONG a8)
    = NULL;

NTSTATUS WINAPI Mine_NtWriteFile(HANDLE a0,
    HANDLE a1,
    PIO_APC_ROUTINE a2,
    PVOID a3,
    PIO_STATUS_BLOCK a4,
    PVOID a5,
    ULONG a6,
    PLARGE_INTEGER a7,
    PULONG a8)
{
    // TODO: There might be recursive calls within syelog's _PrintEnter since it works if it's replaced by print
    // Print spams, however. So not a good Idea to do so.

    //_PrintEnter("NTWriteFile(%p,%p,%p,%p,%p,%p,%p,%p,%p,%p)\n", a0,a1,a2,a3,a4,a5,a6,a7,a8);

    int rv = 0;
    __try {
        rv = Real_NtWriteFile(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    }
    __finally {
        //_PrintExit("AbortDoc() -> %x\n", rv);
    };
    return rv;

    return 0;
}

//
///////////////////////////////////////////////////////////////// End of File.
