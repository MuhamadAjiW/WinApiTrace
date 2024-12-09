#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <winternl.h>
#include <detours/detours.h>

////////////////////////////////////////////////////////////// AttachDetours.
//
static CHAR* DetRealName(const CHAR* psz)
{
    PCHAR retval = const_cast<PCHAR>(psz);
    const CHAR* pszBeg = psz;
    // Move to end of name.
    while (*psz) {
        psz++;
    }
    // Move back through A-Za-z0-9 names.
    while (psz > pszBeg &&
        ((psz[-1] >= 'A' && psz[-1] <= 'Z') ||
            (psz[-1] >= 'a' && psz[-1] <= 'z') ||
            (psz[-1] >= '0' && psz[-1] <= '9'))) {
        psz--;
    }
    return retval;
}

static VOID Dump(PBYTE pbBytes, LONG nBytes, PBYTE pbTarget)
{
    CHAR szBuffer[256];
    PCHAR pszBuffer = szBuffer;

    for (LONG n = 0; n < nBytes; n += 12) {
        pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "  %p: ", pbBytes + n);
        for (LONG m = n; m < n + 12; m++) {
            if (m >= nBytes) {
                pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "   ");
            }
            else {
                pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "%02x ", pbBytes[m]);
            }
        }
        if (n == 0) {
            pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "[%p]", pbTarget);
        }
        pszBuffer += StringCchPrintfA(pszBuffer, sizeof(szBuffer), "\n");
    }

    printf("%s", szBuffer);
}

static VOID Decode(PBYTE pbCode, LONG nInst)
{
    PBYTE pbSrc = pbCode;
    PBYTE pbEnd;
    PBYTE pbTarget;
    for (LONG n = 0; n < nInst; n++) {
        pbTarget = NULL;
        pbEnd = (PBYTE)DetourCopyInstruction(NULL, NULL, (PVOID)pbSrc, (PVOID*)&pbTarget, NULL);
        Dump(pbSrc, (int)(pbEnd - pbSrc), pbTarget);
        pbSrc = pbEnd;

        if (pbTarget != NULL) {
            break;
        }
    }
}

VOID DetAttach(PVOID* ppvReal, PVOID pvMine, const CHAR* psz)
{
    PVOID pvReal = NULL;
    if (ppvReal == NULL) {
        ppvReal = &pvReal;
    }

    LONG l = DetourAttach(ppvReal, pvMine);
    if (l != 0) {
        printf("Attach failed: `%s': error %d\n", DetRealName(psz), l);

        Decode((PBYTE)*ppvReal, 3);
    }
}

VOID DetDetach(PVOID* ppvReal, PVOID pvMine, const CHAR* psz)
{
    LONG l = DetourDetach(ppvReal, pvMine);
    if (l != 0) {
#if 0
        printf("Detach failed: `%s': error %d\n", DetRealName(psz), l);
#else
        (void)psz;
#endif
    }
}

VOID DetAttachNT(PVOID* ppvReal, PVOID pvMine, const CHAR* psz, const WCHAR* lib)
{
    HMODULE hNtdll = LoadLibrary(lib);
    *ppvReal = (PVOID)GetProcAddress(hNtdll, psz);

    LONG l = DetourAttach(ppvReal, pvMine);
    if (l != 0) {
        printf("Attach failed: `%s': error %d\n", DetRealName(psz), l);

        Decode((PBYTE)*ppvReal, 3);
    }
}

VOID DetDetachNT(PVOID* ppvReal, PVOID pvMine, const CHAR* psz)
{
    LONG l = DetourDetach(ppvReal, pvMine);
    if (l != 0) {
#if 0
        printf("Detach failed: `%s': error %d\n", DetRealName(psz), l);
#else
        (void)psz;
#endif
    }
}

#include "_winnt_hooks.cpp"

#define ATTACH(x)           DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define ATTACH_NT(x, lib)   DetAttachNT(&(PVOID&)Real_##x,Mine_##x,#x, lib)
#define DETACH(x)           DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)

void AttachNTHooks()
{
    ATTACH(RegEnumKeyExW);
    ATTACH(CreateDirectoryW);
    ATTACH(DrawTextExW);
    ATTACH_NT(CoInitializeEx, L"ole32.dll");
    ATTACH_NT(NtDeleteKey, L"ntdll.dll");
    ATTACH(SHGetFolderPathW);
    ATTACH_NT(GetFileInformationByHandleEx, L"kernel32.dll");
    ATTACH(GetForegroundWindow);
    ATTACH_NT(NtQueryAttributesFile, L"ntdll.dll");
    ATTACH(DeviceIoControl);
    ATTACH(SearchPathW);
    ATTACH(SetFileTime);
    ATTACH(SendNotifyMessageW);
    ATTACH(GetSystemMetrics);
    ATTACH(GetKeyState);
    ATTACH_NT(NtCreateKey, L"ntdll.dll");
    ATTACH(LoadResource);
    ATTACH(GetDiskFreeSpaceExW);
    ATTACH(EnumWindows);
    ATTACH(RegOpenKeyExW);
    ATTACH_NT(NtQueryKey, L"ntdll.dll");
    ATTACH_NT(NtQueryValueKey, L"ntdll.dll");
    ATTACH_NT(NtSetValueKey, L"ntdll.dll");
    ATTACH(CreateActCtxW);
    ATTACH(GetSystemTimeAsFileTime);
    ATTACH(GetSystemWindowsDirectoryW);
    ATTACH(SetErrorMode);
    ATTACH_NT(GetFileVersionInfoSizeW, L"version.dll");
    ATTACH_NT(NtOpenMutant, L"ntdll.dll");
    ATTACH_NT(NtOpenKey, L"ntdll.dll");
    ATTACH_NT(NtClose, L"ntdll.dll");
    //ATTACH_NT(NtCreateFile, L"ntdll.dll");
    //ATTACH_NT(NtReadFile, L"ntdll.dll");
    //ATTACH_NT(NtWriteFile, L"ntdll.dll");
    ATTACH_NT(LdrGetDllHandle, L"ntdll.dll");
    ATTACH_NT(NtOpenFile, L"ntdll.dll");
    ATTACH_NT(NtFreeVirtualMemory, L"ntdll.dll");

    // _TODO: Figure a better logging system, possibly static
    // These hooks may break the program because logging is done within the memory
    // ATTACH_NT(NtAllocateVirtualMemory, L"ntdll.dll");

    ATTACH_NT(NtProtectVirtualMemory, L"ntdll.dll");

    // _TODO: investigate infinite looping
    // ATTACH_NT(LdrLoadDll, L"ntdll.dll");

    ATTACH_NT(NtQueryInformationFile, L"ntdll.dll");
    ATTACH_NT(NtQueryDirectoryFile, L"ntdll.dll");
}

void DetachNTHooks()
{
    DETACH(RegEnumKeyExW);
    DETACH(CreateDirectoryW);
    DETACH(DrawTextExW);
    DETACH(CoInitializeEx);
    DETACH(NtDeleteKey);
    DETACH(SHGetFolderPathW);
    DETACH(GetFileInformationByHandleEx);
    DETACH(GetForegroundWindow);
    DETACH(NtQueryAttributesFile);
    DETACH(DeviceIoControl);
    DETACH(SearchPathW);
    DETACH(SetFileTime);
    DETACH(SendNotifyMessageW);
    DETACH(GetSystemMetrics);
    DETACH(GetKeyState);
    DETACH(NtCreateKey);
    DETACH(LoadResource);
    DETACH(GetDiskFreeSpaceExW);
    DETACH(EnumWindows);
    DETACH(RegOpenKeyExW);
    DETACH(NtQueryKey);
    DETACH(NtQueryValueKey);
    DETACH(NtSetValueKey);
    DETACH(CreateActCtxW);
    DETACH(GetSystemTimeAsFileTime);
    DETACH(GetSystemWindowsDirectoryW);
    DETACH(SetErrorMode);
    DETACH(GetFileVersionInfoSizeW);
    DETACH(NtOpenMutant);
    DETACH(NtOpenKey);
    DETACH(NtClose);
    //DETACH(NtCreateFile);
    //DETACH(NtReadFile);
    //DETACH(NtWriteFile);
    DETACH(LdrGetDllHandle);
    DETACH(NtOpenFile);
    DETACH(NtFreeVirtualMemory);

    // _TODO: Figure a better logging system, possibly static
    // These hooks may break the program because logging is done within the memory
    // DETACH(NtAllocateVirtualMemory);

    DETACH(NtProtectVirtualMemory);

    // _TODO: investigate infinite looping
    // DETACH(LdrLoadDll);

    DETACH(NtQueryInformationFile);
    DETACH(NtQueryDirectoryFile);
}

LONG AttachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // For this many APIs, we'll ignore one or two can't be detoured.
    DetourSetIgnoreTooSmall(TRUE);

    AttachNTHooks();

    PVOID* ppbFailedPointer = NULL;
    LONG error = DetourTransactionCommitEx(&ppbFailedPointer);
    if (error != 0) {
        printf("traceapi.dll: Attach transaction failed to commit. Error %ld (%p/%p)",
            error, ppbFailedPointer, *ppbFailedPointer);
        return error;
    }
    return 0;
}

LONG DetachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // For this many APIs, we'll ignore one or two can't be detoured.
    DetourSetIgnoreTooSmall(TRUE);

    DetachNTHooks();

    if (DetourTransactionCommit() != 0) {
        PVOID* ppbFailedPointer = NULL;
        LONG error = DetourTransactionCommitEx(&ppbFailedPointer);

        printf("traceapi.dll: Detach transaction failed to commit. Error %ld (%p/%p)",
            error, ppbFailedPointer, *ppbFailedPointer);
        return error;
    }
    return 0;
}

//
///////////////////////////////////////////////////////////////// End of File.
