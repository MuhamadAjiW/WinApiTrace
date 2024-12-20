    #pragma once

#include <iostream>

#include <comdef.h>
#include <WbemIdl.h>
#include <windows.h>
#include <atlbase.h>

class CProcessCreationSink : public IWbemObjectSink {
private:
    long m_refCount;
    VOID(*callback)(IWbemClassObject* pProcess);

public:
    CProcessCreationSink() : m_refCount(1), callback(&DefaultCallback) {}
    CProcessCreationSink(VOID(*customCallback)(IWbemClassObject* pProcess)) : m_refCount(1), callback(customCallback) {}

    static VOID DefaultCallback(IWbemClassObject* pProcess) {
        VARIANT nameVar;
        VARIANT pidVar;

        VariantInit(&nameVar);
        VariantInit(&pidVar);

        pProcess->Get(L"Name", 0, &nameVar, 0, 0);  // Get the Name of the process
        pProcess->Get(L"ProcessId", 0, &pidVar, 0, 0);  // Get the PID of the process
        if (nameVar.vt == VT_BSTR && (pidVar.vt == VT_I4 || pidVar.vt == VT_UI4)) {
            std::wcout << L"Process created: " << nameVar.bstrVal << " (PID: " << pidVar.intVal << ")" << std::endl;
        }
        else {
            std::cout << "Failed to fetch process name and pid" << std::endl;
        }

        VariantClear(&nameVar);
        VariantClear(&pidVar);
    }

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
            IWbemClassObject* pProcess = (IWbemClassObject*)var.punkVal;

            callback(pProcess);

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
