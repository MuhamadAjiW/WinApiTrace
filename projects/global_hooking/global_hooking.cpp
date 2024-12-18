// global_hooking.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>
#include <windows.h>
#include <atlbase.h>


#pragma comment(lib, "wbemuuid.lib")

///////////////////////////////////////////////////////////////// End of File.
//  WMI Setup

HRESULT hres;
ULONG ureturn = 0;
IWbemLocator* pLoc = NULL;
IWbemServices* pSvc = NULL;

int InitializeWMI(){
    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cout << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
        return 1;
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
        std::cout << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // Obtain initial locator to WMI
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc
    );

    if (FAILED(hres)) {
        std::cout << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
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
        std::cout << "Could not connect to WMI. Error code = 0x" << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
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
        std::cout << "Could not set proxy blanker. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    return 0;
}
int UnInitializeWMI() {
    pSvc->Release();
    pLoc->Release();

    CoUninitialize();

    return 0;
}

///////////////////////////////////////////////////////////////// End of File.
//  WMI Commands

int GetOSName() {
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

class CProcessCreationSink : public IWbemObjectSink {
private:
    long m_refCount;

public:
    CProcessCreationSink() : m_refCount(1) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID riid,
        _COM_Outptr_ void** ppvObject) override {

        // Check for supported interfaces
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppvObject = static_cast<IWbemObjectSink*>(this);
            AddRef();  // Increment the reference count
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_refCount);  // Increment reference count atomically
    }

    ULONG STDMETHODCALLTYPE Release() override {
        ULONG ulRefCount = InterlockedDecrement(&m_refCount);  // Decrement reference count atomically
        if (ulRefCount == 0) {
            delete this;  // If reference count reaches zero, delete the object
        }
        return ulRefCount;
    }


    HRESULT STDMETHODCALLTYPE Indicate(
        long lObjectCount,
        __RPC__in_ecount_full(lObjectCount) IWbemClassObject** ppObjArray
    ) override {
        // Iterate over the returned objects
        for (long i = 0; i < lObjectCount; i++) {
            IWbemClassObject* pObj = ppObjArray[i];

            VARIANT var;
            VariantInit(&var);
            pObj->Get(L"TargetInstance", 0, &var, 0, 0);  // Get the TargetInstance property

            IWbemClassObject* pProcess = (IWbemClassObject*) var.punkVal;
            pProcess->Get(L"Name", 0, &var, 0, 0);  // Get the Name of the process

            if (var.vt == VT_BSTR) {
                std::wcout << L"Process created: " << var.bstrVal << std::endl;
            }

            VariantClear(&var);
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetStatus(
        long lFlags,
        HRESULT hResult,
        __RPC__in_opt BSTR strParam,
        __RPC__in_opt IWbemClassObject* pObjParam
    ) override {
        return S_OK;
    }
};

CComPtr<IWbemObjectSink> MonitorProcessCreation() {
    CComPtr<IWbemObjectSink> pSink = new CProcessCreationSink();
    //CComPtr<IWbemObjectSink> pSink = NULL;

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

///////////////////////////////////////////////////////////////// End of File.
//  Main

int main(){
    std::cout << "Starting program\n";

    if (InitializeWMI()) {
        std::cout << "Failed to initialize WMI";
        return 1;
    }

    CComPtr<IWbemObjectSink> pSink = MonitorProcessCreation();

    while (true);

    UnInitializeWMI();
    std::cout << "Program Finished\n";

    return 0;
}
