// global_hooking.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>
#include <windows.h>
#include <atlbase.h>

#include "wmi_libs.h"

#pragma comment(lib, "wbemuuid.lib")

///////////////////////////////////////////////////////////////// End of File.
//  Main

int main(){
    std::cout << "Starting program\n";

    if (InitializeWMI()) {
        std::cout << "Failed to initialize WMI";
        return 1;
    }


    std::cout << "Process creation monitoring started" << std::endl;
    CComPtr<IWbemObjectSink> pSink = MonitorProcessCreation();

    while (true);

    UnInitializeWMI();
    std::cout << "Program Finished\n";

    return 0;
}
