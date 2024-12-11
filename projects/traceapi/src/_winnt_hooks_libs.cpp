
#include <iostream>

#include <windows.h>
#include <wincrypt.h>
#include <security.h>
#include <stdio.h>
#include <winternl.h>
#include <shlobj.h>
#include <detours/detours.h>

#define INCREMENT_WRAP(index, max_size) (((index) + 1) % (max_size))

#define LOG_HOOK_PTR(func_name, param_formats, ...) \
        void* rv = NULL; \
        if (setupCompleted){ \
            std::chrono::high_resolution_clock::time_point call_time = std::chrono::high_resolution_clock::now(); \
            long long relative_time = std::chrono::duration_cast<std::chrono::milliseconds>(call_time - start_time).count(); \
            EnterCriticalSection(&hLock); \
            api_data.api_count[Enum_##func_name]++; \
            LeaveCriticalSection(&hLock); \
        } \
        rv = Real_##func_name(__VA_ARGS__); \
        return rv;

#define LOG_HOOK_HWND(func_name, param_formats, ...) \
        HWND rv = NULL; \
        if (setupCompleted) { \
            std::chrono::high_resolution_clock::time_point call_time = std::chrono::high_resolution_clock::now(); \
            long long relative_time = std::chrono::duration_cast<std::chrono::milliseconds>(call_time - start_time).count(); \
            EnterCriticalSection(&hLock); \
            api_data.api_count[Enum_##func_name]++; \
            LeaveCriticalSection(&hLock); \
        } \
        rv = Real_##func_name(__VA_ARGS__); \
        return rv;

#define LOG_HOOK_VOID(func_name, param_formats, ...) \
        int rv = 0; \
        if (setupCompleted) { \
            std::chrono::high_resolution_clock::time_point call_time = std::chrono::high_resolution_clock::now(); \
            long long relative_time = std::chrono::duration_cast<std::chrono::milliseconds>(call_time - start_time).count(); \
            EnterCriticalSection(&hLock); \
            api_data.api_count[Enum_##func_name]++; \
            LeaveCriticalSection(&hLock); \
        } \
        Real_##func_name(__VA_ARGS__);

#define LOG_HOOK_INT(func_name, param_formats, ...) \
        int rv = 0; \
        if (setupCompleted) { \
            std::chrono::high_resolution_clock::time_point call_time = std::chrono::high_resolution_clock::now(); \
            long long relative_time = std::chrono::duration_cast<std::chrono::milliseconds>(call_time - start_time).count(); \
            EnterCriticalSection(&hLock); \
            api_data.api_count[Enum_##func_name]++; \
            LeaveCriticalSection(&hLock); \
        } \
        rv = Real_##func_name(__VA_ARGS__); \
        return rv;

// void log_parameters_helper(
//     const char* param_formats,
//     const char* param_names,
//     ...)
// {
//     const char* param = param_names;
//     const char* format = param_formats;
//     va_list args;
//     va_start(args, param_names);

//     while (param && *param) {
//         const char* next_comma = strchr(param, ',');
//         if (next_comma == NULL) next_comma = param + strlen(param);

//         char name[256];
//         snprintf(name, next_comma - param + (param == param_names), "%s", param + (param != param_names));

//         switch (*format)
//         {
//         case 'd': // Integer
//             _PrintEnter(";[%s]%d", name, va_arg(args, int));
//             break;
//         case 'l': // Long
//             _PrintEnter(";[%s]%ld", name, va_arg(args, long));
//             break;
//         case 'D': // Unsigned integer
//             _PrintEnter(";[%s]%u", name, va_arg(args, unsigned int));
//             break;
//         case 'L': // Unsigned long
//             _PrintEnter(";[%s]%lu", name, va_arg(args, unsigned long));
//             break;
//         case 'f': // Float
//             _PrintEnter(";[%s]%f", name, va_arg(args, float));
//             break;
//         case 'F': // Double
//             _PrintEnter(";[%s]%lf", name, va_arg(args, double));
//             break;
//         case 'p': // Pointer
//         default:
//             _PrintEnter(";[%s]%p", name, va_arg(args, void*));
//         }

//         param = (*next_comma) ? next_comma + 1 : NULL;
//         format++;
//     }
//     _PrintEnter("\n");

//     va_end(args);
// }

#define PIPE_NAME L"\\Device\\NamedPipe\\ipc_pipe"
#define EVENT_NAME L"\\BaseNamedObjects\\ipc_event"
#define FILE_PIPE_MESSAGE_TYPE 0x00000001
#define FILE_PIPE_MESSAGE_MODE 0x00000001
#define FILE_PIPE_QUEUE_OPERATION 0x00000000

// --Function-Codes--
enum AnalyzedFunctions {
    // Paper functions
    Enum_RegEnumKeyExW,
    Enum_CreateDirectoryW,
    Enum_DrawTextExW,
    Enum_CoInitializeEx,
    Enum_NtDeleteKey,
    Enum_SHGetFolderPathW,
    Enum_GetFileInformationByHandleEx,
    Enum_GetForegroundWindow,
    Enum_NtQueryAttributesFile,
    Enum_DeviceIoControl,
    Enum_SearchPathW,
    Enum_SetFileTime,
    Enum_SendNotifyMessageW,
    Enum_GetSystemMetrics,
    Enum_GetKeyState,
    Enum_NtCreateKey,
    Enum_LoadResource,
    Enum_GetDiskFreeSpaceExW,
    Enum_EnumWindows,
    Enum_RegOpenKeyExW,
    Enum_NtQueryKey,
    Enum_NtQueryValueKey,
    Enum_NtSetValueKey,
    Enum_CreateActCtxW,
    Enum_GetSystemTimeAsFileTime,
    Enum_GetSystemWindowsDirectoryW,
    Enum_SetErrorMode,
    Enum_GetFileVersionInfoSizeW,
    Enum_NtOpenMutant,

    // Additional Functions
    Enum_NtOpenKey,
    Enum_NtClose,
    Enum_NtCreateFile,
    Enum_NtReadFile,
    Enum_NtWriteFile,
    Enum_LdrGetDllHandle,
    Enum_NtOpenFile,
    Enum_NtFreeVirtualMemory,
    Enum_NtAllocateVirtualMemory,
    Enum_NtProtectVirtualMemory,
    Enum_LdrLoadDll,
    Enum_NtQueryInformationFile,
    Enum_NtQueryDirectoryFile
};

// --Communications-API--
NTSTATUS(__stdcall* Real_NtOpenEvent)(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS(__stdcall* Real_NtSetEvent)(
    HANDLE EventHandle,
    PLONG PreviousState);

VOID(__stdcall* Real_RtlInitUnicodeString)(
    PUNICODE_STRING         DestinationString,
    __drv_aliasesMem PCWSTR SourceString);

NTSTATUS status = { 0 };
IO_STATUS_BLOCK ioStatusBlock = { 0 };

HANDLE hEvent = { 0 };
UNICODE_STRING eventName = { 0 };
OBJECT_ATTRIBUTES eventAttr = { 0 };

HANDLE hPipe = { 0 };
UNICODE_STRING pipeName = { 0 };
OBJECT_ATTRIBUTES pipeAttr = { 0 };

HANDLE hCommsThread;
DWORD dwCommsThread;

APIDATA_SINGLE apidata_tosend;

// --Move up--
DWORD WINAPI sendRoutine(LPVOID lpParam);

// --Functions--
VOID fetchNTFunc(PVOID* ppvReal, const CHAR* psz, const WCHAR* lib) {
    HMODULE hNtdll = LoadLibrary(lib);
    *ppvReal = (PVOID)GetProcAddress(hNtdll, psz);
}

void setupComms() {
    InitializeCriticalSection(&hLock);
    fetchNTFunc(&(PVOID&)Real_NtOpenFile, "NtOpenFile", L"ntdll.dll");
    fetchNTFunc(&(PVOID&)Real_NtWriteFile, "NtWriteFile", L"ntdll.dll");
    fetchNTFunc(&(PVOID&)Real_NtClose, "NtClose", L"ntdll.dll");
    fetchNTFunc(&(PVOID&)Real_NtOpenEvent, "NtOpenEvent", L"ntdll.dll");
    fetchNTFunc(&(PVOID&)Real_NtSetEvent, "NtSetEvent", L"ntdll.dll");
    fetchNTFunc(&(PVOID&)Real_RtlInitUnicodeString, "RtlInitUnicodeString", L"ntdll.dll");

    // Init pipe
    Real_RtlInitUnicodeString(&pipeName, PIPE_NAME);
    InitializeObjectAttributes(
        &pipeAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    // Init event
    Real_RtlInitUnicodeString(&eventName, EVENT_NAME);
    InitializeObjectAttributes(
        &eventAttr,
        &eventName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = Real_NtOpenEvent(
        &hEvent,
        EVENT_ALL_ACCESS,
        &eventAttr
    );

    commsSending = TRUE;
    hCommsThread = CreateThread(
        NULL,
        0,
        sendRoutine,
        NULL,
        0,
        &dwCommsThread
    );
}

void sendData() {
    // Get pipe
    ioStatusBlock = { 0 };
    status = Real_NtOpenFile(
        &hPipe,
        GENERIC_READ | GENERIC_WRITE,
        &pipeAttr,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        0
    );

    // Send data
    ioStatusBlock = { 0 };
    // const char* send = "Hello!";
    status = Real_NtWriteFile(
        hPipe,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        (void*)&apidata_tosend,
        sizeof(apidata_tosend),
        //(void*)&api_data,
        //sizeof(api_data),
        NULL,
        NULL
    );

    // Trigger Event
    status = Real_NtSetEvent(
        hEvent,
        NULL
    );

    status = Real_NtClose(hPipe);
}

DWORD WINAPI sendRoutine(LPVOID lpParam) {
    std::chrono::high_resolution_clock::time_point call_time = std::chrono::high_resolution_clock::now();
    double relative_time = std::chrono::duration<double, std::milli>(call_time - start_time).count();

    while (!setupCompleted) {}

    Sleep(COLLECTED_API_TIME_RANGE);
    while (commsSending) {
        /**/
        /**
        std::chrono::high_resolution_clock::time_point curr_time1 = std::chrono::high_resolution_clock::now();
        long long relative_time1 = std::chrono::duration_cast<std::chrono::microseconds>(curr_time1 - start_time).count();
        std::cout << "about to print at " << relative_time1 << std::endl;
        /**
        std::cout << "offset: " << static_cast<int>(api_data.offset) << std::endl;
        for (size_t frame = 0; frame < COLLECTED_API_TIME_RANGE_STEPS; frame++)
        {
            std::cout << "[";
            for (size_t i = 0; i < COLLECTED_API_COUNT; i++) {
                std::cout << apidata_tosend.api_count[frame][i] << ",";
            }
            std::cout << "]" << std::endl;
        }

        std::chrono::high_resolution_clock::time_point curr_time2 = std::chrono::high_resolution_clock::now();
        long long relative_time2 = std::chrono::duration_cast<std::chrono::microseconds>(curr_time2 - start_time).count();
        std::cout << "about to send at " << relative_time2 << std::endl;
        /**/
        apidata_tosend.offset = api_data.offset;
        EnterCriticalSection(&hLock);
        memcpy(apidata_tosend.api_count, api_data.api_count, sizeof(apidata_tosend.api_count));
        memset(api_data.api_count, 0, sizeof(api_data.api_count));
        LeaveCriticalSection(&hLock);
        sendData();
        //api_data.offset = INCREMENT_WRAP(api_data.offset, COLLECTED_API_TIME_RANGE_STEPS);
        api_data.offset++;

        std::chrono::high_resolution_clock::time_point pre_sleep_time = std::chrono::high_resolution_clock::now();
        long long relative_ps_time = std::chrono::duration_cast<std::chrono::microseconds>(pre_sleep_time - call_time).count();
        int relative_ps_time_mod = relative_ps_time % (COLLECTED_API_TIME_DELAY * 1000);
        int sleep_length = COLLECTED_API_TIME_DELAY - relative_ps_time_mod / 1000;
        //std::cout << "about to print at " << relative_time1 << std::endl;
        Sleep(sleep_length);
    }

    return 0;
}

void closeComms() {
    commsSending = FALSE;
    status = Real_NtClose(hPipe);
    status = Real_NtClose(hEvent);
    DeleteCriticalSection(&hLock);
}