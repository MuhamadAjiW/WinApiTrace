// _TODO: Work on hooking NT API's

#define SECURITY_WIN32

#include <iostream>

#include <windows.h>
#include <wincrypt.h>
#include <security.h>
#include <stdio.h>
#include <winternl.h>
#include <shlobj.h>
#include <detours/detours.h>

// --Structs--
typedef struct __CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} *PCLIENT_ID;

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3,
    KeyCachedInformation = 4,
    KeyFlagsInformation = 5,
    KeyVirtualizationInformation = 6,
    KeyHandleTagsInformation = 7,
    MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK LDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    const LDR_DLL_NOTIFICATION_DATA* NotificationData,
    VOID* Context);

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef enum _FILE_INFO_BY_HANDLE_CLASS {
    FileBasicInfo,
    FileStandardInfo,
    FileNameInfo,
    FileRenameInfo,
    FileDispositionInfo,
    FileAllocationInfo,
    FileEndOfFileInfo,
    FileStreamInfo,
    FileCompressionInfo,
    FileAttributeTagInfo,
    FileIdBothDirectoryInfo,
    FileIdBothDirectoryRestartInfo,
    FileIoPriorityHintInfo,
    FileRemoteProtocolInfo,
    FileFullDirectoryInfo,
    FileFullDirectoryRestartInfo,
    FileStorageInfo,
    FileAlignmentInfo,
    FileIdInfo,
    FileIdExtdDirectoryInfo,
    FileIdExtdDirectoryRestartInfo,
    FileDispositionInfoEx,
    FileRenameInfoEx,
    FileCaseSensitiveInfo,
    FileNormalizedNameInfo,
    MaximumFileInfoByHandleClass
} FILE_INFO_BY_HANDLE_CLASS, * PFILE_INFO_BY_HANDLE_CLASS;

// --Real-Paper-Functions--
LSTATUS(__stdcall* Real_RegEnumKeyExW)(
    HKEY      hKey,
    DWORD     dwIndex,
    LPWSTR    lpName,
    LPDWORD   lpcchName,
    LPDWORD   lpReserved,
    LPWSTR    lpClass,
    LPDWORD   lpcchClass,
    PFILETIME lpftLastWriteTime) = RegEnumKeyExW;

BOOL(__stdcall* Real_CreateDirectoryW)(
    LPCWSTR lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes) = CreateDirectoryW;

int(__stdcall* Real_DrawTextExW)(
    HDC hdc,
    LPWSTR lpchText,
    int cchText,
    LPRECT lprc,
    UINT format,
    LPDRAWTEXTPARAMS lpdtp) = DrawTextExW;

HRESULT(__stdcall* Real_CoInitializeEx)(
    LPVOID pvReserved,
    DWORD  dwCoInit);

NTSTATUS(__stdcall* Real_NtDeleteKey)(
    HANDLE KeyHandle);

HRESULT(__stdcall* Real_SHGetFolderPathW)(
    HWND hwnd,
    int csidl,
    HANDLE hToken,
    DWORD dwFlags,
    LPWSTR pszPath) = SHGetFolderPathW;

BOOL(__stdcall* Real_GetFileInformationByHandleEx)(
    HANDLE hFile,
    FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID lpFileInformation,
    DWORD dwBufferSize);

HWND(__stdcall* Real_GetForegroundWindow)(VOID) = GetForegroundWindow;

NTSTATUS(__stdcall* Real_NtQueryAttributesFile)(
    POBJECT_ATTRIBUTES      ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation);

BOOL(__stdcall* Real_DeviceIoControl)(
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped) = DeviceIoControl;

DWORD(__stdcall* Real_SearchPathW)(
    LPCWSTR lpPath,
    LPCWSTR lpFileName,
    LPCWSTR lpExtension,
    DWORD nBufferLength,
    LPWSTR lpBuffer,
    LPWSTR* lpFilePart) = SearchPathW;

BOOL(__stdcall* Real_SetFileTime)(
    HANDLE hFile,
    const FILETIME* lpCreationTime,
    const FILETIME* lpLastAccessTime,
    const FILETIME* lpLastWriteTime) = SetFileTime;

BOOL(__stdcall* Real_SendNotifyMessageW)(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam) = SendNotifyMessageW;

int(__stdcall* Real_GetSystemMetrics)(
    int nIndex) = GetSystemMetrics;

SHORT(__stdcall* Real_GetKeyState)(
    int nVirtKey) = GetKeyState;

NTSTATUS(__stdcall* Real_NtCreateKey)(
    PHANDLE pKeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition);

HGLOBAL(__stdcall* Real_LoadResource)(
    HMODULE hModule,
    HRSRC hResInfo) = LoadResource;

BOOL(__stdcall* Real_GetDiskFreeSpaceExW)(
    LPCWSTR lpDirectoryName,
    PULARGE_INTEGER lpFreeBytesAvailableToCaller,
    PULARGE_INTEGER lpTotalNumberOfBytes,
    PULARGE_INTEGER lpTotalNumberOfFreeBytes) = GetDiskFreeSpaceExW;

BOOL(__stdcall* Real_EnumWindows)(
    WNDENUMPROC lpEnumFunc,
    LPARAM lParam) = EnumWindows;

LSTATUS(__stdcall* Real_RegOpenKeyExW)(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult) = RegOpenKeyExW;

NTSTATUS(__stdcall* Real_NtQueryKey)(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

NTSTATUS(__stdcall* Real_NtQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength);

NTSTATUS(__stdcall* Real_NtSetValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize);

HANDLE(__stdcall* Real_CreateActCtxW)(
    PCACTCTXW pActCtx) = CreateActCtxW;

void(__stdcall* Real_GetSystemTimeAsFileTime)(
    LPFILETIME lpSystemTimeAsFileTime) = GetSystemTimeAsFileTime;

UINT(__stdcall* Real_GetSystemWindowsDirectoryW)(
    LPWSTR lpBuffer,
    UINT uSize) = GetSystemWindowsDirectoryW;

UINT(__stdcall* Real_SetErrorMode)(
    UINT uMode) = SetErrorMode;

DWORD(__stdcall* Real_GetFileVersionInfoSizeW)(
    LPCWSTR lptstrFilename,
    LPDWORD lpdwHandle);

NTSTATUS(__stdcall* Real_NtOpenMutant)(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);


// --Real-Additional-Functions--
NTSTATUS(__stdcall* Real_NtOpenKey)(
    PHANDLE pKeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS(__stdcall* Real_NtClose)(
    HANDLE Handle);

NTSTATUS(__stdcall* Real_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength);

NTSTATUS(__stdcall* Real_NtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key);

NTSTATUS(__stdcall* Real_NtWriteFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key);

NTSTATUS(__stdcall* Real_LdrGetDllHandle)(
    PWORD pwPath,
    PVOID Unused,
    PUNICODE_STRING ModuleFileName,
    PHANDLE pHModule);

NTSTATUS(__stdcall* Real_NtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions);

NTSTATUS(__stdcall* Real_NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    CONST VOID** BaseAddress,
    SIZE_T* RegionSize,
    ULONG FreeType);

NTSTATUS(__stdcall* Real_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    VOID** BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T* RegionSize,
    ULONG AllocationType,
    ULONG Protect);

NTSTATUS(__stdcall* Real_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    CONST VOID** BaseAddress,
    SIZE_T* NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    ULONG* OldAccessProtection);

NTSTATUS(__stdcall* Real_LdrLoadDll)(
    PWCHAR PathToFile,
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle);

NTSTATUS(__stdcall* Real_NtQueryInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS(__stdcall* Real_NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileMask,
    BOOLEAN RestartScan);

// --Libs--
#include "_winnt_hooks_libs.cpp"

// --Hooked-Paper-Functions--
LSTATUS Mine_RegEnumKeyExW(
    HKEY      hKey,
    DWORD     dwIndex,
    LPWSTR    lpName,
    LPDWORD   lpcchName,
    LPDWORD   lpReserved,
    LPWSTR    lpClass,
    LPDWORD   lpcchClass,
    PFILETIME lpftLastWriteTime)
{
    LOG_HOOK_INT(
        RegEnumKeyExW,
        "pLpppppp",
        hKey,
        dwIndex,
        lpName,
        lpcchName,
        lpReserved,
        lpClass,
        lpcchClass,
        lpftLastWriteTime
    );
}

BOOL Mine_CreateDirectoryW(
    LPCWSTR lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    LOG_HOOK_INT(
        CreateDirectoryW,
        "pp",
        lpPathName,
        lpSecurityAttributes
    );
}

int Mine_DrawTextExW(
    HDC hdc,
    LPWSTR lpchText,
    int cchText,
    LPRECT lprc,
    UINT format,
    LPDRAWTEXTPARAMS lpdtp)
{
    LOG_HOOK_INT(
        DrawTextExW,
        "ppdpDp",
        hdc,
        lpchText,
        cchText,
        lprc,
        format,
        lpdtp
    );
}

HRESULT Mine_CoInitializeEx(
    LPVOID pvReserved,
    DWORD  dwCoInit)
{
    LOG_HOOK_INT(
        CoInitializeEx,
        "pL",
        pvReserved,
        dwCoInit
    );
}

NTSTATUS Mine_NtDeleteKey(
    HANDLE KeyHandle)
{
    LOG_HOOK_INT(
        NtDeleteKey,
        "p",
        KeyHandle
    );
}

HRESULT Mine_SHGetFolderPathW(
    HWND hwnd,
    int csidl,
    HANDLE hToken,
    DWORD dwFlags,
    LPWSTR pszPath)
{
    LOG_HOOK_INT(
        SHGetFolderPathW,
        "pdpLp",
        hwnd,
        csidl,
        hToken,
        dwFlags,
        pszPath
    );
}

BOOL Mine_GetFileInformationByHandleEx(
    HANDLE hFile,
    FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID lpFileInformation,
    DWORD dwBufferSize)
{
    LOG_HOOK_INT(
        GetFileInformationByHandleEx,
        "pppL",
        hFile,
        FileInformationClass,
        lpFileInformation,
        dwBufferSize
    );
}

HWND Mine_GetForegroundWindow(VOID)
{
    LOG_HOOK_HWND(
        GetForegroundWindow,
        ""
    );
}

NTSTATUS Mine_NtQueryAttributesFile(
    POBJECT_ATTRIBUTES      ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation)
{
    LOG_HOOK_INT(
        NtQueryAttributesFile,
        "pp",
        ObjectAttributes,
        FileInformation
    );
}

BOOL Mine_DeviceIoControl(
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped)
{
    LOG_HOOK_INT(
        DeviceIoControl,
        "pLpLpLpp",
        hDevice,
        dwIoControlCode,
        lpInBuffer,
        nInBufferSize,
        lpOutBuffer,
        nOutBufferSize,
        lpBytesReturned,
        lpOverlapped
    );
}

DWORD Mine_SearchPathW(
    LPCWSTR lpPath,
    LPCWSTR lpFileName,
    LPCWSTR lpExtension,
    DWORD nBufferLength,
    LPWSTR lpBuffer,
    LPWSTR* lpFilePart)
{
    LOG_HOOK_INT(
        SearchPathW,
        "pppLpp",
        lpPath,
        lpFileName,
        lpExtension,
        nBufferLength,
        lpBuffer,
        lpFilePart
    );
}

BOOL Mine_SetFileTime(
    HANDLE hFile,
    const FILETIME* lpCreationTime,
    const FILETIME* lpLastAccessTime,
    const FILETIME* lpLastWriteTime)
{
    LOG_HOOK_INT(
        SetFileTime,
        "pppp",
        hFile,
        lpCreationTime,
        lpLastAccessTime,
        lpLastWriteTime
    );
}

BOOL Mine_SendNotifyMessageW(
    HWND hWnd,
    UINT Msg,
    WPARAM wParam,
    LPARAM lParam)
{
    LOG_HOOK_INT(
        SendNotifyMessageW,
        "pDpp",
        hWnd,
        Msg,
        wParam,
        lParam
    );
}

int Mine_GetSystemMetrics(
    int nIndex)
{
    LOG_HOOK_INT(
        GetSystemMetrics,
        "d",
        nIndex
    );
}

SHORT Mine_GetKeyState(
    int nVirtKey)
{
    LOG_HOOK_INT(
        GetKeyState,
        "d",
        nVirtKey
    );
}

NTSTATUS Mine_NtCreateKey(
    PHANDLE pKeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition)
{
    LOG_HOOK_INT(
        NtCreateKey,
        "pLpLpLp",
        pKeyHandle,
        DesiredAccess,
        ObjectAttributes,
        TitleIndex,
        Class,
        CreateOptions,
        Disposition
    );
}

HGLOBAL Mine_LoadResource(
    HMODULE hModule,
    HRSRC hResInfo)
{
    LOG_HOOK_PTR(
        LoadResource,
        "pp",
        hModule,
        hResInfo
    );
}

BOOL Mine_GetDiskFreeSpaceExW(
    LPCWSTR lpDirectoryName,
    PULARGE_INTEGER lpFreeBytesAvailableToCaller,
    PULARGE_INTEGER lpTotalNumberOfBytes,
    PULARGE_INTEGER lpTotalNumberOfFreeBytes)
{
    LOG_HOOK_INT(
        GetDiskFreeSpaceExW,
        "pppp",
        lpDirectoryName,
        lpFreeBytesAvailableToCaller,
        lpTotalNumberOfBytes,
        lpTotalNumberOfFreeBytes
    );
}

BOOL Mine_EnumWindows(
    WNDENUMPROC lpEnumFunc,
    LPARAM lParam)
{
    LOG_HOOK_INT(
        EnumWindows,
        "pp",
        lpEnumFunc,
        lParam
    );
}

LSTATUS Mine_RegOpenKeyExW(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult)
{
    LOG_HOOK_INT(
        RegOpenKeyExW,
        "ppLpp",
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult
    );
}

NTSTATUS Mine_NtQueryKey(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength)
{
    LOG_HOOK_INT(
        NtQueryKey,
        "pppLp",
        KeyHandle,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength
    );
}

NTSTATUS Mine_NtQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength)
{
    LOG_HOOK_INT(
        NtQueryValueKey,
        "ppppLp",
        KeyHandle,
        ValueName,
        KeyValueInformationClass,
        KeyValueInformation,
        Length,
        ResultLength
    );
}

NTSTATUS Mine_NtSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize)
{
    LOG_HOOK_INT(
        NtSetValueKey,
        "ppLLpL",
        KeyHandle,
        ValueName,
        TitleIndex,
        Type,
        Data,
        DataSize
    );
}

HANDLE Mine_CreateActCtxW(
    PCACTCTXW pActCtx)
{
    LOG_HOOK_PTR(
        CreateActCtxW,
        "p",
        pActCtx
    );
}

void Mine_GetSystemTimeAsFileTime(
    LPFILETIME lpSystemTimeAsFileTime)
{
    LOG_HOOK_VOID(
        GetSystemTimeAsFileTime,
        "p",
        lpSystemTimeAsFileTime
    );
}

UINT Mine_GetSystemWindowsDirectoryW(
    LPWSTR lpBuffer,
    UINT uSize)
{
    LOG_HOOK_INT(
        GetSystemWindowsDirectoryW,
        "pD",
        lpBuffer,
        uSize
    );
}

UINT Mine_SetErrorMode(
    UINT uMode)
{
    LOG_HOOK_INT(
        SetErrorMode,
        "D",
        uMode
    );
}

DWORD Mine_GetFileVersionInfoSizeW(
    LPCWSTR lptstrFilename,
    LPDWORD lpdwHandle)
{
    LOG_HOOK_INT(
        GetFileVersionInfoSizeW,
        "pp",
        lptstrFilename,
        lpdwHandle
    );
}

NTSTATUS Mine_NtOpenMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes)
{
    LOG_HOOK_INT(
        NtOpenMutant,
        "pLp",
        MutantHandle,
        DesiredAccess,
        ObjectAttributes
    );
}


// --Hooked-Additional-Functions--
NTSTATUS Mine_NtOpenKey(
    PHANDLE pKeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes)
{
    LOG_HOOK_INT(
        NtOpenKey,
        "pLp",
        pKeyHandle,
        DesiredAccess,
        ObjectAttributes
    );
}

NTSTATUS Mine_NtClose(
    HANDLE Handle)
{
    LOG_HOOK_INT(
        NtClose,
        "p",
        Handle
    );
}

NTSTATUS Mine_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength)
{
    LOG_HOOK_INT(
        NtCreateFile,
        "pLpppLLLLpL",
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength
    );
}

NTSTATUS Mine_NtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    LOG_HOOK_INT(
        NtReadFile,
        "ppppppLpp",
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key
    );
}

NTSTATUS Mine_NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    LOG_HOOK_INT(
        NtWriteFile,
        "ppppppLpp",
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key
    );
}

NTSTATUS Mine_LdrGetDllHandle(
    PWORD pwPath,
    PVOID Unused,
    PUNICODE_STRING ModuleFileName,
    PHANDLE pHModule)
{
    LOG_HOOK_INT(
        LdrGetDllHandle,
        "pppp",
        pwPath,
        Unused,
        ModuleFileName,
        pHModule
    );
}

NTSTATUS Mine_NtOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions)
{
    LOG_HOOK_INT(
        NtOpenFile,
        "ppppLL",
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        ShareAccess,
        OpenOptions
    );
}

NTSTATUS Mine_NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    CONST VOID** BaseAddress,
    SIZE_T* RegionSize,
    ULONG FreeType)
{
    LOG_HOOK_INT(
        NtFreeVirtualMemory,
        "pppL",
        ProcessHandle,
        BaseAddress,
        RegionSize,
        FreeType
    );
}

NTSTATUS Mine_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    VOID** BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T* RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    LOG_HOOK_INT(
        NtAllocateVirtualMemory,
        "ppppLL",
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    );
}

NTSTATUS Mine_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    CONST VOID** BaseAddress,
    SIZE_T* NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    ULONG* OldAccessProtection)
{
    LOG_HOOK_INT(
        NtProtectVirtualMemory,
        "pppLp",
        ProcessHandle,
        BaseAddress,
        NumberOfBytesToProtect,
        NewAccessProtection,
        OldAccessProtection
    );
}

NTSTATUS Mine_LdrLoadDll(
    PWCHAR PathToFile,
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle)
{
    LOG_HOOK_INT(
        LdrLoadDll,
        "pLpp",
        PathToFile,
        Flags,
        ModuleFileName,
        ModuleHandle
    );
}

NTSTATUS Mine_NtQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass)
{
    LOG_HOOK_INT(
        NtQueryInformationFile,
        "pppLp",
        FileHandle,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass
    );
}

NTSTATUS Mine_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileMask,
    BOOLEAN RestartScan)
{
    LOG_HOOK_INT(
        NtQueryDirectoryFile,
        "ppppppLpdpd",
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        ReturnSingleEntry,
        FileMask,
        RestartScan
    );
}


//
///////////////////////////////////////////////////////////////// End of File.
