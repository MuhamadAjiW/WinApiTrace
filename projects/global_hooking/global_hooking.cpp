// global_hooking.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>
#include <windows.h>
#include <atlbase.h>

#include "WMIWrapper.hpp"
#include "CProcessCreationSink.hpp"

#pragma comment(lib, "wbemuuid.lib")

/////////////////////////////////////////////////////////////////
//  Main

VOID HookProcess(IWbemClassObject* pProcess) {
    VARIANT pidVar;

    VariantInit(&pidVar);

    pProcess->Get(L"ProcessId", 0, &pidVar, 0, 0);  // Get the PID of the process
    if (!(pidVar.vt == VT_I4 || pidVar.vt == VT_UI4)) {
        std::cout << "Failed to fetch process name and pid" << std::endl;
        return;
    }
    int pid = pidVar.intVal;
    std::wcout << L"Process created (PID: " << pid << ")" << std::endl;

    //std::wstring dllLocation = L"C:\\thing.dll";
    //HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, pid);

    //const size_t size = (dllLocation.length() + 1) * sizeof(wchar_t);
    //void* remotePtr = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    //WriteProcessMemory(hProcess, remotePtr, dllLocation.c_str(), size, nullptr);
    //CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibrary), remotePtr, 0, nullptr);

    VariantClear(&pidVar);
}

int main() {
    std::cout << "Starting program\n";
    WMIWrapper wmi = WMIWrapper();

    std::cout << "Process creation monitoring started" << std::endl;
    CComPtr<IWbemObjectSink> pSink = wmi.MonitorProcessCreation(HookProcess);

    while (true);

    wmi.StopMonitoring(pSink);
    std::cout << "Program Finished\n";

    return 0;
}
