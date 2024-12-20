#include <comdef.h>
#include <WbemIdl.h>
#include <windows.h>
#include <atlbase.h>

#include <stdexcept>
#include <string>
#include <sstream>
#include <iostream>

#include "CProcessCreationSink.hpp"

class WMIWrapper {
private:
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
public:
    /////////////////////////////////////////////////////////////////
    //  WMI Setup
    WMIWrapper() {
        HRESULT hres;

        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            throw std::runtime_error([&]() {
                std::ostringstream oss;
                oss << "Failed to initialize COM library. Error code = 0x" << std::hex << hres;
                return oss.str();
                }());
        }

        // Initialize Security
        hres = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE,
            NULL
        );
        if (FAILED(hres)) {
            CoUninitialize();
            throw std::runtime_error([&]() {
                std::ostringstream oss;
                oss << "Failed to initialize security. Error code = 0x"
                    << std::hex << hres << std::endl;
                return oss.str();
                }());

        }

        // Obtain initial locator to WMI
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc
        );

        if (FAILED(hres)) {
            CoUninitialize();
            throw std::runtime_error([&]() {
                std::ostringstream oss;
                oss << "Failed to create IWbemLocator object. Error code = 0x"
                    << std::hex << hres << std::endl;
                return oss.str();
                }());
        }

        // Connect to WMI
        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            NULL,
            NULL,
            0,
            NULL,
            0,
            0,
            &pSvc
        );
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            throw std::runtime_error([&]() {
                std::ostringstream oss;
                oss << "Could not connect to WMI. Error code = 0x"
                    << std::hex << hres << std::endl;
                return oss.str();
                }());
        }

        // Set security levels on the proxy
        hres = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );
        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            throw std::runtime_error([&]() {
                std::ostringstream oss;
                oss << "Could not set proxy blanker. Error code = 0x"
                    << std::hex << hres << std::endl;
                return oss.str();
                }());
        }
    }

    ~WMIWrapper() {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
    }

    /////////////////////////////////////////////////////////////////
    //  WMI Commands

    int GetOSName() {
        HRESULT hres;

        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_OperatingSystem"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        if (FAILED(hres)) {
            std::cout << "Query for operating system name failed. Error code = 0x" << std::hex << hres << std::endl;
            return 1;
        }

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (uReturn == 0) break;

            VARIANT vtProp;
            VariantInit(&vtProp);

            hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            std::wcout << "OS Name: " << vtProp.bstrVal << std::endl;
            VariantClear(&vtProp);

            pclsObj->Release();
        }
        pEnumerator->Release();

        return 0;
    }

    CComPtr<IWbemObjectSink> MonitorProcessCreation(){
        return MonitorProcessCreation(&CProcessCreationSink::DefaultCallback);
    }

    CComPtr<IWbemObjectSink> MonitorProcessCreation(
        VOID(*callback)(IWbemClassObject* pProcess)
    ) {
        HRESULT hres;
        CComPtr<IWbemObjectSink> pSink = new CProcessCreationSink(callback);

        hres = pSvc->ExecNotificationQueryAsync(
            _bstr_t(L"WQL"),
            _bstr_t(L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
            0,
            NULL,
            pSink
        );
        if (FAILED(hres)) {
            std::cout << "Query for process creation failed. Error code = 0x" << std::hex << hres << std::endl;
        }

        return pSink;
    }

    void StopMonitoring(CComPtr<IWbemObjectSink> pSink) {
        HRESULT hres;

        hres = pSvc->CancelAsyncCall(pSink);
        if (SUCCEEDED(hres)) {
            std::cout << "Stopped monitoring." << std::endl;
        }
        else {
            std::cout << "Failed to stop monitoring. Error code = 0x" << std::hex << hres << std::endl;
        }
    }
};