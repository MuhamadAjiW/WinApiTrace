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
    _PrintEnter("NtWriteFile(%p,%p,%p,%p,%p,%p,%p,%p,%p,%p)\n", a0,a1,a2,a3,a4,a5,a6,a7,a8);

    proof_NT_works++;

    int rv = 0;
    __try {
        rv = Real_NtWriteFile(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    }
    __finally {
        _PrintExit("NtWriteFile() -> %x\n", rv);
    };
    return rv;
}

//
///////////////////////////////////////////////////////////////// End of File.
