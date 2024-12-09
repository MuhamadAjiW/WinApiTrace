//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (trcapi.cpp of trcapi.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#undef WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT        0x0501
#define WIN32
#define NT
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define DBG_TRACE   0

#if _MSC_VER >= 1300
#include <winsock2.h>
#endif
#include <windows.h>
#include <stdio.h>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable:6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)
#include <detours/detours.h>
#include <string>
#include <chrono>

#if (_MSC_VER < 1299)
#define LONG_PTR    LONG
#define ULONG_PTR   ULONG
#define PLONG_PTR   PLONG
#define PULONG_PTR  PULONG
#define INT_PTR     INT
#define UINT_PTR    UINT
#define PINT_PTR    PINT
#define PUINT_PTR   PUINT
#define DWORD_PTR   DWORD
#define PDWORD_PTR  PDWORD
#endif

#pragma warning(disable:4996)   // We don't care about deprecated APIs.

//////////////////////////////////////////////////////////////////////////////
#pragma warning(disable:4127)   // Many of our asserts are constants.

#define ASSERT_ALWAYS(x)   \
    do {                                                        \
    if (!(x)) {                                                 \
            AssertMessage(#x, __FILE__, __LINE__);              \
            DebugBreak();                                       \
    }                                                           \
    } while (0)

#ifndef NDEBUG
#define ASSERT(x)           ASSERT_ALWAYS(x)
#else
#define ASSERT(x)
#endif

#define UNUSED(c)    (c) = (c)

//////////////////////////////////////////////////////////////////////////////
static HMODULE s_hInst = NULL;
static WCHAR s_wzDllPath[MAX_PATH];
static CHAR s_szDllPath[MAX_PATH];

BOOL ProcessEnumerate();
BOOL InstanceEnumerate(HINSTANCE hInst);

VOID _PrintEnter(const CHAR* psz, ...);
VOID _PrintExit(const CHAR* psz, ...);
VOID _Print(const CHAR* psz, ...);

VOID AssertMessage(CONST CHAR* pszMsg, CONST CHAR* pszFile, ULONG nLine);

//////////////////////////////////////////////////////////////////////////////

BOOL s_bLog = FALSE;
LONG s_nTlsIndent = -1;
LONG s_nTlsThread = -1;
LONG s_nThreadCnt = 0;
std::string output_string = "";
std::chrono::high_resolution_clock::time_point start_time;
BOOLEAN commsSending;

// _NOTE: Now before you start blaming me on including c files and not using header files.
// There are tons of problems from winapi if we do so
// This simplifies lots of stuff, especially for an MVP
#include "attach_hooks.cpp"

////////////////////////////////////////////////////////////// Logging System.
//

void str_concatf(std::string* str, const char* __restrict pattern, ...) {
    va_list args;
    va_start(args, pattern);
    int len = vsnprintf(NULL, 0, pattern, args) + 1;
    va_end(args);

    char* content = (char*)malloc(len);
    if (content == NULL) return;

    va_start(args, pattern);
    vsnprintf(content, len, pattern, args);
    va_end(args);

    str->append(content);

    free(content);
}

VOID _PrintEnter(const CHAR* psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
        TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)(nIndent + 1));
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        // _NOTE: Recursion data, uncomment if needed

        //CHAR szBuf[1024];
        //PCHAR pszBuf = szBuf;
        //PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
        //LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        //*pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        //*pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        //*pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        //*pszBuf++ = ' ';
        //while (nLen-- > 0) {
        //    *pszBuf++ = ' ';
        //}
        //*pszBuf++ = '+';
        //*pszBuf = '\0';

        //output_string.append(szBuf);

        // Function data
        va_list args;
        va_start(args, psz);
        int len = vsnprintf(NULL, 0, psz, args) + 1;
        va_end(args);

        char* content = (char*)malloc(len);
        if (content == NULL) return;

        va_start(args, psz);
        vsnprintf(content, len, psz, args);
        va_end(args);

        output_string.append(content);

        free(content);
    }
    SetLastError(dwErr);
}

VOID _PrintExit(const CHAR* psz, ...)
{
    // _NOTE: Return function data, uncomment if needed

    //DWORD dwErr = GetLastError();

    //LONG nIndent = 0;
    //LONG nThread = 0;
    //if (s_nTlsIndent >= 0) {
    //    nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent) - 1;
    //    ASSERT_ALWAYS(nIndent >= 0);
    //    TlsSetValue(s_nTlsIndent, (PVOID)(LONG_PTR)nIndent);
    //}
    //if (s_nTlsThread >= 0) {
    //    nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    //}

    //if (s_bLog && psz) {
    //    CHAR szBuf[1024];
    //    PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
    //    PCHAR pszBuf = szBuf;
    //    LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
    //    *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
    //    *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
    //    *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
    //    *pszBuf++ = ' ';
    //    while (nLen-- > 0) {
    //        *pszBuf++ = ' ';
    //    }
    //    *pszBuf++ = '-';
    //    *pszBuf = '\0';

    //    va_list  args;
    //    va_start(args, psz);

    //    while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
    //        // Copy characters.
    //    }
    //    *pszEnd = '\0';
    //    output_string.append(szBuf);

    //    va_end(args);
    //}
    //SetLastError(dwErr);
}

VOID _Print(const CHAR* psz, ...)
{
    DWORD dwErr = GetLastError();

    LONG nIndent = 0;
    LONG nThread = 0;
    if (s_nTlsIndent >= 0) {
        nIndent = (LONG)(LONG_PTR)TlsGetValue(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        nThread = (LONG)(LONG_PTR)TlsGetValue(s_nTlsThread);
    }

    if (s_bLog && psz) {
        CHAR szBuf[1024];
        PCHAR pszEnd = szBuf + ARRAYSIZE(szBuf) - 1;
        PCHAR pszBuf = szBuf;
        LONG nLen = (nIndent > 0) ? (nIndent < 35 ? nIndent * 2 : 70) : 0;
        *pszBuf++ = (CHAR)('0' + ((nThread / 100) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 10) % 10));
        *pszBuf++ = (CHAR)('0' + ((nThread / 1) % 10));
        *pszBuf++ = ' ';
        while (nLen-- > 0) {
            *pszBuf++ = ' ';
        }
        *pszBuf = '\0';

        va_list  args;
        va_start(args, psz);

        while ((*pszBuf++ = *psz++) != 0 && pszBuf < pszEnd) {
            // Copy characters.
        }
        *pszEnd = '\0';
        output_string.append(szBuf);

        va_end(args);
    }
    SetLastError(dwErr);
}

VOID AssertMessage(CONST CHAR* pszMsg, CONST CHAR* pszFile, ULONG nLine)
{
    str_concatf(&output_string, "ASSERT(%s) failed in %s, line %d.\n", pszMsg, pszFile, nLine);
}

//////////////////////////////////////////////////////////////////////////////
//
PIMAGE_NT_HEADERS NtHeadersForInstance(HINSTANCE hInst)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hInst;
    __try {
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            return NULL;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
            pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_INVALID_EXE_SIGNATURE);
            return NULL;
        }
        if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0) {
            SetLastError(ERROR_EXE_MARKED_INVALID);
            return NULL;
        }
        return pNtHeader;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    SetLastError(ERROR_EXE_MARKED_INVALID);

    return NULL;
}

BOOL InstanceEnumerate(HINSTANCE hInst)
{
    WCHAR wzDllName[MAX_PATH];

    PIMAGE_NT_HEADERS pinh = NtHeadersForInstance(hInst);
    if (pinh && GetModuleFileNameW(hInst, wzDllName, ARRAYSIZE(wzDllName))) {
        // NOTE: Instance enumeration, uncomment str_concatf if necessary
        //str_concatf(&output_string, "### %p: %ls\n", hInst, wzDllName);
        return TRUE;
    }
    return FALSE;
}

BOOL ProcessEnumerate()
{
    // NOTE: Process enumeration, uncomment str_concatf if necessary
    //str_concatf(&output_string, "######################################################### Binaries\n");

    PBYTE pbNext;
    for (PBYTE pbRegion = (PBYTE)0x10000;; pbRegion = pbNext) {
        MEMORY_BASIC_INFORMATION mbi;
        ZeroMemory(&mbi, sizeof(mbi));

        if (VirtualQuery((PVOID)pbRegion, &mbi, sizeof(mbi)) <= 0) {
            break;
        }
        pbNext = (PBYTE)mbi.BaseAddress + mbi.RegionSize;

        // Skip free regions, reserver regions, and guard pages.
        //
        if (mbi.State == MEM_FREE || mbi.State == MEM_RESERVE) {
            continue;
        }
        if (mbi.Protect & PAGE_GUARD || mbi.Protect & PAGE_NOCACHE) {
            continue;
        }
        if (mbi.Protect == PAGE_NOACCESS) {
            continue;
        }

        // Skip over regions from the same allocation...
        {
            MEMORY_BASIC_INFORMATION mbiStep;

            while (VirtualQuery((PVOID)pbNext, &mbiStep, sizeof(mbiStep)) > 0) {
                if ((PBYTE)mbiStep.AllocationBase != pbRegion) {
                    break;
                }
                pbNext = (PBYTE)mbiStep.BaseAddress + mbiStep.RegionSize;
                mbi.Protect |= mbiStep.Protect;
            }
        }

        WCHAR wzDllName[MAX_PATH];
        PIMAGE_NT_HEADERS pinh = NtHeadersForInstance((HINSTANCE)pbRegion);

        if (pinh &&
            GetModuleFileNameW((HINSTANCE)pbRegion, wzDllName, ARRAYSIZE(wzDllName))) {

            //str_concatf(&output_string, "### %p..%p: %ls\n", pbRegion, pbNext, wzDllName);
        }
        else {
            //str_concatf(&output_string,"### %p..%p: State=%04x, Protect=%08x\n",
            //    pbRegion, pbNext, mbi.State, mbi.Protect);
        }
    }
    //str_concatf(&output_string, "###\n");

    LPVOID lpvEnv = GetEnvironmentStrings();
    //str_concatf(&output_string, "### Env= %08x [%08x %08x]\n",
    //    lpvEnv, ((PVOID*)lpvEnv)[0], ((PVOID*)lpvEnv)[1]);

    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
//
// DLL module information
//
BOOL ThreadAttach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        LONG nThread = InterlockedIncrement(&s_nThreadCnt);
        TlsSetValue(s_nTlsThread, (PVOID)(LONG_PTR)nThread);
    }
    return TRUE;
}

BOOL ThreadDetach(HMODULE hDll)
{
    (void)hDll;

    if (s_nTlsIndent >= 0) {
        TlsSetValue(s_nTlsIndent, (PVOID)0);
    }
    if (s_nTlsThread >= 0) {
        TlsSetValue(s_nTlsThread, (PVOID)0);
    }
    return TRUE;
}

BOOL ProcessAttach(HMODULE hDll)
{
    setupComms();

    s_bLog = FALSE;
    s_nTlsIndent = TlsAlloc();
    s_nTlsThread = TlsAlloc();
    ThreadAttach(hDll);

    WCHAR wzExeName[MAX_PATH];

    s_hInst = hDll;
    GetModuleFileNameW(hDll, s_wzDllPath, ARRAYSIZE(s_wzDllPath));
    GetModuleFileNameW(NULL, wzExeName, ARRAYSIZE(wzExeName));
    StringCchPrintfA(s_szDllPath, ARRAYSIZE(s_szDllPath), "%ls", s_wzDllPath);

    ProcessEnumerate();

    LONG error = AttachDetours();
    if (error != NO_ERROR) {
        str_concatf(&output_string, "### Error attaching detours: %d\n", error);
    }

    s_bLog = TRUE;
    start_time = std::chrono::high_resolution_clock::now();
    return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
    ThreadDetach(hDll);
    s_bLog = FALSE;

    LONG error = DetachDetours();
    if (error != NO_ERROR) {
        str_concatf(&output_string, "### Error detaching detours: %d\n", error);
    }

    str_concatf(&output_string, "### Closing.\n");

    if (s_nTlsIndent >= 0) {
        TlsFree(s_nTlsIndent);
    }
    if (s_nTlsThread >= 0) {
        TlsFree(s_nTlsThread);
    }

    sendData();
    closeComms();

    return TRUE;
}

__declspec(dllexport) BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;
    BOOL ret;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        OutputDebugStringA("trcapi" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
            " DllMain DLL_PROCESS_ATTACH\n");
        return ProcessAttach(hModule);
    case DLL_PROCESS_DETACH:
        ret = ProcessDetach(hModule);
        OutputDebugStringA("trcapi" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
            " DllMain DLL_PROCESS_DETACH\n");
        std::cout << output_string << std::endl;
        return ret;
    case DLL_THREAD_ATTACH:
        OutputDebugStringA("trcapi" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
            " DllMain DLL_THREAD_ATTACH\n");
        return ThreadAttach(hModule);
    case DLL_THREAD_DETACH:
        OutputDebugStringA("trcapi" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
            " DllMain DLL_THREAD_DETACH\n");
        return ThreadDetach(hModule);
    }
    return TRUE;
}
//
///////////////////////////////////////////////////////////////// End of File.
