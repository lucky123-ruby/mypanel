#pragma once
#define INITGUID
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <setupapi.h>
#include <devguid.h>
#include <wincrypt.h>
#include <winioctl.h>
#include <string>
#include <vector>
#include <random>
#include <atomic>
#include <mutex>
#include <array>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "crypt32.lib")

// 使用系统定义的NT_SUCCESS宏
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((极NTSTATUS)(Status)) >= 0)
#endif

// 避免PROCESS_BASIC_INFORMATION重定义
#ifndef _PROCESS_BASIC_INFORMATION_DEFINED
#define _PROCESS_BASIC_INFORMATION极_DEFINED
#endif

// 避免与winternl.h中的定义冲突
#ifdef _PROCESSINFOCLASS_DEFINED
// 如果系统头文件已定义，则使用系统的定义
#else
#define _PROCESSINFOCLASS_DEFINED
namespace MyAntiAnalysis {
    enum _PROCESSINFOCLASS {
        ProcessDebugPort = 7,
        ProcessDebugObjectHandle = 30
    };
}
#endif

// 类型定义
typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONPROCESS)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

// TLS回调早期反调试 - 在入口点前执行
//#pragma comment(linker, "/INCLUDE:__tls_used")
// 全局变量定义
/*std::atomic<bool> g_bDebuggerDetected(false);
std::atomic<bool> g_bSandboxDetected(false);

// TLS回调数组定义
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK tls_callbacks[] = { TlsCallback, nullptr };
#pragma data_seg()
*/
// 先声明TLS回调函数
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved);
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK tls_callbacks[] = { TlsCallback, nullptr };
#pragma data_seg()
// 全局标记 - 使用原子操作确保极线程安全
std::atomic<bool> g_bDebuggerDetected(false);
std::atomic<bool> g_bSandboxDetected(false);
// 加密密钥（使用常量而非动态生成减少可疑行为）
constexpr DWORD XOR_KEY = 0xDEADBEEF;
// 高级调试器检测函数

// 调试器存在时的安全响应函数

// 缓存时序检测函数（修复tsc2变量）
__forceinline bool CheckCacheTiming() {
    const int ITERATIONS = 100000;
    const int ARRAY_SIZE = 1024 * 1024;
    volatile char* array = new char[ARRAY_SIZE];
    unsigned __int64 tsc1, tsc2, sum = 0; // 修复：正确定义tsc1和tsc2

    for (int i = 0; i < ITERATIONS; ++i) {
        int index = (i * 9973) % ARRAY_SIZE;
        tsc1 = __rdtsc();
        array[index] = static_cast<char>(i);
        tsc2 = __rdtsc(); // 修复：正确使用已定义的tsc2
        sum += tsc2 - tsc1;
    }
    delete[] array;
    return (sum / ITERATIONS) > 150;
}
// 代码混淆技术 - 控制流扁平化
__forceinline void ObfuscatedExecution() {
    DWORD controlFlowKey = 0xDEADBEEF;
    while (true) {
        switch (controlFlowKey) {
        case 0xDEADBEEF:
            _mm_pause();
            _mm_pause();
            controlFlowKey = 0xCAFEBABE;
            break;
        case 0xCAFEBABE:
            controlFlowKey = 0xBAADF00D;
            break;
        case 0xBAADF00D:
            if (GetTickCount() % 2 == 0) {
                controlFlowKey = 0x12345678;
            }
            else {
                controlFlowKey = 0xABCDEF01;
            }
            break;
        case 0x12345678:
            return;
        default:
            controlFlowKey = 0xDEADBEEF;
        }
    }
}

// 增强版反虚拟机检测

// 字符串加密（避免静态分析检测敏感字符串）
__forceinline wchar_t* DecryptString(const wchar_t* encrypted, size_t length) {
    wchar_t* decrypted = new wchar_t[length + 1];
    for (size_t i = 0; i < length; i++) {
        decrypted[i] = encrypted[i] ^ (XOR_KEY >> (i % 32));
    }
    decrypted[length] = L'\0';
    return decrypted;
}

// 窗口枚举回调数据结构
struct EnumData {
    const std::vector<std::wstring>* keywords;
    int matchCount;
};

// 窗口枚举回调
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumData* data = reinterpret_cast<EnumData*>(lParam);
    wchar_t windowTitle[256] = { 0 };

    if (GetWindowTextW(hwnd, windowTitle, ARRAYSIZE(windowTitle))) {
        for (const auto& keyword : *data->keywords) {
            if (wcsstr(windowTitle, keyword.c_str())) {
                data->matchCount++;
                if (data->matchCount >= 2) {
                    return FALSE;
                }
                break;
            }
        }
    }
    return TRUE;
}

// 新增：动态资源压力测试（检测沙箱资源限制）
__forceinline bool CheckResourceResponse() {
    const size_t chunkSize = 1024 * 1024 * 100;
    const int testCycles = 2;
    using namespace std::chrono;
    auto start = high_resolution_clock::now();

    for (int i = 0; i < testCycles; ++i) {
        std::vector<char> memoryBuffer;
        try {
            memoryBuffer.resize(chunkSize);
            for (auto& c : memoryBuffer) c = static_cast<char>(rand() % 256);
            memoryBuffer[rand() % chunkSize] = 0;
        }
        catch (...) {
            return true;
        }
    }
    auto duration = duration_cast<milliseconds>(high_resolution_clock::now() - start).count();
    return duration < (testCycles * 800);
}

// 新增：PCI设备拓扑分析（检测虚拟化环境设备信息缺失）
__forceinline bool CheckPciDeviceDepth() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_DISPLAY, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return true;

    DWORD deviceCount = 0;
    SP_DEVINFO_DATA devInfoData = { 0 };
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); ++i) {
        WCHAR enumeratorName[256];
        DWORD dataType, requiredSize = 0;
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_ENUMERATOR_NAME, &dataType, (PBYTE)enumeratorName, sizeof(enumeratorName), &requiredSize)) {
            if (wcscmp(enumeratorName, L"PCI") == 0) {
                deviceCount++;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return deviceCount < 2;
}

// 新增：多级缓存时序检测（识别虚拟化环境指令模拟开销）

// 新增：输入事件模式建模（检测缺乏真实用户交互极的沙箱环境）
__forceinline bool CheckHumanLikeInput() {
    POINT prevPos, currPos;
    if (!GetCursorPos(&prevPos)) return true;

    double totalDistance = 0;
    int samples = 0;
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    while (true) {
        Sleep(50);
        if (!GetCursorPos(&currPos)) break;

        double dx = static_cast<double>(currPos.x - prevPos.x);
        double dy = static_cast<double>(currPos.y - prevPos.y);
        totalDistance += sqrt(dx * dx + dy * dy);
        samples++;
        prevPos = currPos;

        QueryPerformanceCounter(&end);
        if ((end.QuadPart - start.QuadPart) / static_cast<double>(freq.QuadPart) > 2.0) break;
    }
    if (samples == 0) return true;
    double avgSpeed = totalDistance / samples;
    return (avgSpeed < 0.1) || (avgSpeed > 1000);
}

// 新增：存储介质物理特征检测（识别虚拟磁盘）
__forceinline bool CheckDiskGeometry() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return true;

    DISK_GEOMETRY_EX geo = { 0 };
    DWORD bytesReturned;
    BOOL success = DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &geo, sizeof(geo), &bytesReturned, NULL);
    CloseHandle(hDevice);

    if (!success) return true;
    return (geo.Geometry.BytesPerSector != 512) || (geo.DiskSize.QuadPart < 20LL * 1024 * 1024 * 1024);
}

// 新增：数字证书链验证（检查虚拟机厂商证书）
__forceinline bool CheckVMwareCert() {
    HCERTSTORE hStore = CertOpenSystemStore(0, L"CA");
    if (!hStore) return false;

    bool found = false;
    PCCERT_CONTEXT pCert = NULL;
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        DWORD infoSize = 0;
        if (CertGetCertificateContextProperty(pCert, CERT_FRIENDLY_NAME_PROP_ID, NULL, &infoSize)) {
            LPWSTR name = (LPWSTR)LocalAlloc(LPTR, infoSize);
            if (name && CertGetCertificateContextProperty(pCert, CERT_FRIENDLY_NAME_PROP_ID, name, &infoSize)) {
                if (wcsstr(name, L"VMware") || wcsstr(name, L"VirtualBox") || wcsstr(name, L"极QEMU")) {
                    found = true;
                    LocalFree(name);
                    break;
                }
            }
            if (name) LocalFree(name);
        }
    }
    CertCloseStore(hStore, 0);
    return found;
}

// 新增：睡眠加速检测（对抗沙箱的时间加速策略）
__forceinline bool CheckSleepAcceleration() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(1000);
    QueryPerformanceCounter(&end);

    double actualSleepTime = (end.QuadPart - start.QuadPart) / static_cast<double>(freq.QuadPart);
    return actualSleepTime < 0.8;
}

// 新增：低进程数检测（沙箱环境通常进程较少）
__forceinline bool CheckLowProcessCount() {
    DWORD pids[1024];
    DWORD bytesReturned;
    if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) return false;
    DWORD processCount = bytesReturned / sizeof(DWORD);
    return processCount < 50;
}

// 新增：屏幕分辨率检测（沙箱常使用标准化分辨率）
__forceinline bool CheckStandardResolution() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    return (width == 1024 && height == 768) || (width == 1280 && height == 1024) || (width == 800 && height == 600);
}

// 高级调试器检测
__forceinline bool CheckAdvancedDebuggersEarly() {
    // 1. 检查PEB中的调试标志 (x64平台使用GS寄存器，偏移0x60获取PEB指针，PEB的BeingDebugged字段偏移为0.2)
    PVOID pPeb = reinterpret_cast<PVOID>(__readgsqword(0x60));
    if (static_cast<BYTE*>(pPeb)[2] != 0) return true;

    // 2. 极检查NtGlobalFlag (PEB中偏移0xBC)
    if (*(DWORD*)(static_cast<BYTE*>(pPeb) + 0xBC) == 0x70) return true;

    // 3. 检查调试对象
    constexpr DWORD ProcessDebugObjectHandle = 0x1E; // 手动定义枚举值

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto NtQueryInfoProc = reinterpret_cast<NTQUERYINFORMATIONPROCESS>(
            GetProcAddress(hNtdll, "NtQueryInformationProcess"));
        if (NtQueryInfoProc) {
            HANDLE hDebugObject = nullptr;
            NTSTATUS status = NtQueryInfoProc(GetCurrentProcess(),
                static_cast<PROCESSINFOCLASS>(ProcessDebugObjectHandle),
                &hDebugObject,
                sizeof(HANDLE),
                nullptr);
            if (NT_SUCCESS(status) && hDebugObject != nullptr) {
                CloseHandle(hDebugObject);
                return true;

            }
        }
    }
    return false;
}

// 扫描入口点断点
__forceinline void ScanForEntryPointBreakpoints() {
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return;

    BYTE* entryPoint = (BYTE*)hModule + pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    for (int i = 0; i < 20; i++) {
        if (entryPoint[i] == 0xCC) {
            ExitProcess(0);
        }
    }
}

// TLS回调函数
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason != DLL_PROCESS_ATTACH) return;

    if (CheckAdvancedDebuggersEarly()) {
        ExitProcess(0);
    }

    ScanForEntryPointBreakpoints();
}

// 多维度环境检测
__forceinline bool CheckAdvancedDebuggers() {
    if (IsDebuggerPresent()) return true;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    auto NtQueryInformationProcess = reinterpret_cast<NTQUERYINFORMATIONPROCESS>(
        GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) return false;

    DWORD debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(ProcessDebugPort), &debugPort, sizeof(debugPort), NULL);
    if (NT_SUCCESS(status) && debugPort != 0) return true;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    volatile DWORD junk = 0;
    for (int i = 0; i < 1000000; ++i) { junk += i * i; }

    QueryPerformanceCounter(&end);
    double time = (end.QuadPart - start.QuadPart) / static_cast<double>(freq.QuadPart);
    if (time > 0.1) return true;

    return false;
}

// 增强版反虚拟机检测
__forceinline bool IsInsideVM() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) return true;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }

    // 新增的深度沙箱检测手段
    if (CheckResourceResponse()) return true;
    if (CheckPciDeviceDepth()) return true;
    if (CheckCacheTiming()) return true;
    if (CheckDiskGeometry()) return true;
    if (CheckVMwareCert()) return true;
    if (CheckLowProcessCount()) return true;
    if (CheckStandardResolution()) return true;
    if (CheckHumanLikeInput()) return true;
    if (CheckSleepAcceleration()) return true;

    return false;
}

// 分析工具进程检测（使用加密字符串）
__forceinline bool DetectAnalysisTools() {
    static const wchar_t* encryptedNames[] = {
        L"\x8CEC\x8CE6\x8CEA\x8CEF\x8CE1\x8CE4\x8CE5\x8CE2\x8CEE", // x64dbg.exe
        L"\x8CEC\x8CE6\x8CEA\x8CEF\x8CE1\x8CE4\x8CE5\x8CE2\x8CEE", // x32dbg.exe
        L"\x8CEF\x8CEC\x8CEC\x8CF3\x8CE1\x8CE4\x8CE5\x8CE2\x8CEE", // ollydbg.exe
        L"\x8CE9\x8CE1\x8CF1\x8CF4\x8CE6\x8CE4\x8CE5\x8CE2\x8CEE", // idaq64.exe
        L"\x8CE9\x8CE1\x8CF1\x8CF4\x8CE6\x8CE4\x8CE5\x8CE2\x8CEE"  // idaq.exe
    };

    const size_t nameCount = sizeof(encryptedNames) / sizeof(encryptedNames[0]);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    BOOL found = FALSE;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            for (size_t i = 0; i < nameCount; i++) {
                wchar_t* realName = DecryptString(encryptedNames[i], wcslen(encryptedNames[i]));
                if (wcscmp(pe.szExeFile, realName) == 0) {
                    found = TRUE;
                    delete[] realName;
                    break;
                }
                delete[] realName;
            }
            if (found) break;
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return found;
}

// 代码混淆技术 - 控制流扁平化


// 安全的内存操作
__forceinline bool SafeMemoryOperation(void* dest, const void* src, size_t size) {
    __try {
        memcpy(dest, src, size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;

    }
}

// 调试器存在时的安全响应
__forceinline void Break极IfDebugged() {
    __try {
        int* ptr = nullptr;
        *ptr = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    ObfuscatedExecution();
}
__forceinline void BreakIfDebugged() {
    __try {
        // 触发异常以干扰调试器
        DebugBreak();
        // 或者使用内存访问异常
        int* ptr = nullptr;
        *ptr = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 异常处理代码
    }

    // 混淆执行路径
    ObfuscatedExecution();

    // 可选：退出进程
    ExitProcess(0);
}

// 监视线程函数，持续检测调试器窗口
DWORD WINAPI MonitorDebuggerWindow(LPVOID) {
    std::vector<std::wstring> keywords = {
        L"OllyDbg", L"IDA", L"x64dbg", L"WinDbg", L"Debug", L"DBG"
    };

    while (!g_bDebuggerDetected) {
        EnumData data = { &keywords, 0 };
        EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&data));

        if (data.matchCount >= 2) {
            g_bDebuggerDetected = true;
            BreakIfDebugged();
            break;
        }

        Sleep(1000 + rand() % 2000);
    }
    return 0;
}

// 主反分析函数
void AntiAnalysisMain() {
    HANDLE hThread = CreateThread(nullptr, 0, MonitorDebuggerWindow, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);

    if (CheckAdvancedDebuggers() || IsInsideVM() || DetectAnalysisTools()) {
        g_bDebuggerDetected = true;
        BreakIfDebugged();
        return;
    }

    MessageBoxW(nullptr, L"应用程序正常运行", L"状态", MB_OK);
}

// 主函数
int mainfunction() {
    srand(static_cast<unsigned int>(time(nullptr)));
    AntiAnalysisMain();
    return 0;
}