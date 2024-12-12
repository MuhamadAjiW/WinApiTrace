
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

