#pragma once

#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>
#include <windows.h>
#include <atlbase.h>

#include "CProcessCreationSink.hpp"

///////////////////////////////////////////////////////////////// End of File.
//  WMI Setup

int InitializeWMI();
int UnInitializeWMI();

///////////////////////////////////////////////////////////////// End of File.
//  WMI Commands

int GetOSName();
CComPtr<IWbemObjectSink> MonitorProcessCreation();