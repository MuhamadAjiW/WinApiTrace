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

int main() {
    std::cout << "Starting program\n";
    WMIWrapper wmi = WMIWrapper();

    std::cout << "Process creation monitoring started" << std::endl;
    CComPtr<IWbemObjectSink> pSink = wmi.MonitorProcessCreation();

    while (true);

    wmi.StopMonitoring(pSink);
    std::cout << "Program Finished\n";

    return 0;
}
