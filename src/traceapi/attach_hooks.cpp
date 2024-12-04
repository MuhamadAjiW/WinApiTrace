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

VOID DetAttachNT(PVOID* ppvReal, PVOID pvMine, const CHAR* psz)
{
    HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
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

#include <traceapi/_winnt_hooks.cpp>

#define ATTACH(x)           DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH(x)           DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)
#define ATTACH_NT(x)        DetAttachNT(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH_NT(x)        DetDetachNT(&(PVOID&)Real_##x,Mine_##x,#x)

void AttachNTHooks()
{

    ATTACH_NT(NtWriteFile);
    ATTACH_NT(NtFreeVirtualMemory);
    ATTACH_NT(NtProtectVirtualMemory);
    ATTACH_NT(NtQueryKey);

    // ATTACH(RegEnumKeyExW);
    // ATTACH(CreateDirectoryW);
    // ATTACH(DrawTextExW);
    // ATTACH(CoInitializeEx);
    // ATTACH(NtDeleteKey);

    // // _TODO: investigate proper return value
    // //ATTACH(SHGetFolderPathW);

    // ATTACH(GetFileInformationByHandleEx);
    // ATTACH(GetForegroundWindow);
    // ATTACH(NtQueryAttributesFile);
    // ATTACH(DeviceIoControl);
    // ATTACH(SearchPathW);
    // ATTACH(SetFileTime);
    // ATTACH(SendNotifyMessageW);
    // ATTACH(GetSystemMetrics);
    // ATTACH(GetKeyState);
    // ATTACH(NtCreateKey);
    // ATTACH(LoadResource);
    // ATTACH(GetDiskFreeSpaceExW);
    // ATTACH(EnumWindows);
    // ATTACH(RegOpenKeyExW);
    // ATTACH(NtQueryKey);
    // ATTACH(NtQueryValueKey);
    // ATTACH(NtSetValueKey);
    // ATTACH(CreateActCtxW);
    // ATTACH(GetSystemTimeAsFileTime);
    // ATTACH(GetSystemWindowsDirectoryW);
    // ATTACH(SetErrorMode);
    // ATTACH(GetFileVersionInfoSizeW);
    // ATTACH(NtOpenMutant);
    // ATTACH(NtOpenKey);
    // ATTACH(NtClose);
    // ATTACH(NtCreateFile);
    // ATTACH(NtReadFile);
    // ATTACH(NtWriteFile);
    // ATTACH(LdrGetDllHandle);
    // ATTACH(NtOpenFile);
    // ATTACH(NtFreeVirtualMemory);

    // // _TODO: Figure a better logging system, possibly static
    // // These hooks may break the program because logging is done within the memory
    // //ATTACH_NT(NtAllocateVirtualMemory);

    // ATTACH(NtProtectVirtualMemory);
    // ATTACH(LdrLoadDll);
    // ATTACH(NtQueryInformationFile);
    // ATTACH(NtQueryDirectoryFile);
}

void DetachNTHooks()
{
    DETACH_NT(NtWriteFile);
    DETACH_NT(NtFreeVirtualMemory);
    DETACH_NT(NtProtectVirtualMemory);
    DETACH_NT(NtQueryKey);

    // _TODO: Figure a better logging system, possibly static
    // These hooks may break the program because logging is done within the memory
    //DETACH_NT(NtAllocateVirtualMemory);
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
