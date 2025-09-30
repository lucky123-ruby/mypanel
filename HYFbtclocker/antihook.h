#pragma once
#pragma once
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <string>
#include <vector>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

class CAntiHookEngine {
private:
    // �ڴ汣�������� - ʹ��RAIIģʽȷ����ȫ
    class CMemoryProtector {
    public:
        CMemoryProtector(void* address, SIZE_T size, DWORD newProtection)
            : m_address(address), m_size(size), m_success(false) {
            m_success = !!VirtualProtect(address, size, newProtection, &m_oldProtection);
        }

        ~CMemoryProtector() {
            if (m_success) {
                DWORD temp;
                VirtualProtect(m_address, m_size, m_oldProtection, &temp);
            }
        }

        bool IsSuccessful() const { return m_success; }

    private:
        void* m_address;
        SIZE_T m_size;
        DWORD m_oldProtection;
        bool m_success;
    };

    // PE�ļ������� - ��ȫ��д�汾
    class CPEAnalyzer {
    public:
        static DWORD ConvertRVAtoFileOffset(DWORD rva, BYTE* moduleBase) {
            if (!moduleBase) return 0;

            PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

            PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
                moduleBase + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

            // ��ȡ����ͷ
            PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            WORD sectionCount = ntHeaders->FileHeader.NumberOfSections;

            // �������н������Ұ�����RVA�Ľ���
            for (WORD i = 0; i < sectionCount; ++i) {
                DWORD sectionStart = sectionHeader[i].VirtualAddress;
                DWORD sectionEnd = sectionStart +
                    (sectionHeader[i].SizeOfRawData > sectionHeader[i].Misc.VirtualSize ?
                        sectionHeader[i].SizeOfRawData : sectionHeader[i].Misc.VirtualSize);

                if (rva >= sectionStart && rva < sectionEnd) {
                    return rva - sectionStart + sectionHeader[i].PointerToRawData;
                }
            }

            return rva; // ���û���ҵ���Ӧ������������ͷ������
        }

        static bool IsValidPEFile(BYTE* fileData) {
            if (!fileData) return false;

            PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileData);
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

            PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
                fileData + dosHeader->e_lfanew);
            return ntHeaders->Signature == IMAGE_NT_SIGNATURE;
        }
    };

    // �ַ����������� - ʹ�ò�ͬ�Ļ����㷨
    class CStringObfuscator {
    private:
        static const BYTE OBFUSCATION_KEYS[4];

    public:
        static std::string DeobfuscateString(const char* obfuscated, size_t length) {
            std::string result;
            result.reserve(length);

            for (size_t i = 0; i < length; ++i) {
                BYTE key = OBFUSCATION_KEYS[i % 4];
                result.push_back(obfuscated[i] ^ key);
            }

            return result;
        }

        static const char* GetObfuscatedModuleName(int index) {
            static const char* obfuscatedNames[] = {
                "\x56\x56\x4B\x4B\x4E\x4E\x55\x55\x5C\x0D\x4E\x4E\x55", // kernel32.dll
                "\x50\x4C\x5D\x0D\x5D\x5C\x0D\x4E\x4E\x55",           // ntdll.dll
                "\x46\x4D\x4F\x4A\x4E\x4A\x5D\x5C\x0D\x4E\x4E\x55",   // advapi32.dll
                "\x51\x5D\x5C\x5D\x5B\x5D\x4A\x56\x55\x0D\x4E\x4E\x55", // ws2_32.dll
                "\x57\x5C\x55\x55\x4E\x55\x0D\x4E\x4E\x55",           // shell32.dll
                "\x51\x48\x4C\x57\x4A\x56\x4A\x0D\x4E\x4E\x55",       // shlwapi.dll
                "\x57\x4E\x5D\x48\x4C\x56\x4A\x0D\x4E\x4E\x55",      // ole32.dll
                "\x57\x4E\x55\x4A\x5D\x5D\x0D\x4E\x4E\x55"            // oleaut32.dll
            };

            if (index >= 0 && index < static_cast<int>(sizeof(obfuscatedNames) / sizeof(obfuscatedNames[0]))) {
                return obfuscatedNames[index];
            }
            return nullptr;
        }
    };

    // ���Ӽ���߼� - ��ȫ��д�ļ���㷨
    class CHookDetector {
    public:
        static bool IsFunctionHooked(const BYTE* originalCode, const BYTE* memoryCode, size_t checkSize = 16) {
            if (!originalCode || !memoryCode) return false;

            // �����תָ��ģʽ
            if (memoryCode[0] == 0xE9) return true; // JMP��Ե�ַ
            if (memoryCode[0] == 0xFF && memoryCode[1] == 0x25) return true; // JMP���Ե�ַ
            if (memoryCode[0] == 0x68 && memoryCode[5] == 0xC3) return true; // PUSH + RETģʽ

            // ����ֽڱȽ�
            return !CompareMemoryBlocks(originalCode, memoryCode, checkSize);
        }

        static bool IsForwarderFunction(const BYTE* functionData) {
            if (!functionData) return false;

            // ת������ͨ����"DLL��.������"��ʽ
            int consecutiveValidChars = 0;
            for (int i = 0; i < 128 && functionData[i] != 0; ++i) {
                BYTE c = functionData[i];
                bool isValidChar = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';

                if (isValidChar) {
                    consecutiveValidChars++;
                    if (consecutiveValidChars > 8) return true; // ���ַ����ܿ�����ת����
                }
                else {
                    consecutiveValidChars = 0;
                }
            }

            return false;
        }

    private:
        static bool CompareMemoryBlocks(const BYTE* block1, const BYTE* block2, size_t size) {
            for (size_t i = 0; i < size; ++i) {
                if (block1[i] != block2[i]) {
                    return false;
                }
            }
            return true;
        }
    };

public:
    // ���ӿ� - ������йؼ�ϵͳģ��Ĺ���
    static bool RemoveAllHooks() {
        const char* criticalModules[] = {
            "kernel32.dll", "ntdll.dll", "advapi32.dll",
            "ws2_32.dll", "shell32.dll", "shlwapi.dll",
            "ole32.dll", "oleaut32.dll"
        };

        bool overallSuccess = true;
        for (int i = 0; i < sizeof(criticalModules) / sizeof(criticalModules[0]); ++i) {
            if (!ProcessSingleModule(criticalModules[i])) {
                overallSuccess = false;
            }
        }

        return overallSuccess;
    }

    // ����ض�ģ���������
    static bool RemoveHooksForModule(const char* moduleName) {
        return ProcessSingleModule(moduleName);
    }

private:
    static bool ProcessSingleModule(const char* moduleName) {
        HMODULE hModule = ::LoadLibraryA(moduleName);
        if (!hModule) return false;

        bool result = ScanAndRepairModule(hModule);
        ::FreeLibrary(hModule);

        return result;
    }

    static bool ScanAndRepairModule(HMODULE hModule) {
        CHAR modulePath[MAX_PATH];
        if (!::GetModuleFileNameA(hModule, modulePath, MAX_PATH)) {
            return false;
        }

        // �򿪴����ϵ�ԭʼDLL�ļ�
        HANDLE hFile = ::CreateFileA(modulePath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        // �����ļ�ӳ��
        HANDLE hMapping = ::CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!hMapping) {
            ::CloseHandle(hFile);
            return false;
        }

        // ӳ����ͼ
        LPVOID pMappedFile = ::MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!pMappedFile) {
            ::CloseHandle(hMapping);
            ::CloseHandle(hFile);
            return false;
        }

        bool success = AnalyzeAndFixExports(static_cast<BYTE*>(pMappedFile), hModule);

        ::UnmapViewOfFile(pMappedFile);
        ::CloseHandle(hMapping);
        ::CloseHandle(hFile);

        return success;
    }

    static bool AnalyzeAndFixExports(BYTE* fileData, HMODULE loadedModule) {
        if (!CPEAnalyzer::IsValidPEFile(fileData)) return false;

        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileData);
        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(fileData + dosHeader->e_lfanew);

        DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportDirRVA) return false;

        DWORD exportDirOffset = CPEAnalyzer::ConvertRVAtoFileOffset(exportDirRVA, fileData);
        PIMAGE_EXPORT_DIRECTORY exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(fileData + exportDirOffset);

        DWORD* nameRVAs = reinterpret_cast<DWORD*>(fileData +
            CPEAnalyzer::ConvertRVAtoFileOffset(exportDir->AddressOfNames, fileData));
        WORD* ordinalTable = reinterpret_cast<WORD*>(fileData +
            CPEAnalyzer::ConvertRVAtoFileOffset(exportDir->AddressOfNameOrdinals, fileData));
        DWORD* functionRVAs = reinterpret_cast<DWORD*>(fileData +
            CPEAnalyzer::ConvertRVAtoFileOffset(exportDir->AddressOfFunctions, fileData));

        bool anyHooksFixed = false;

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
            DWORD nameOffset = CPEAnalyzer::ConvertRVAtoFileOffset(nameRVAs[i], fileData);
            const char* functionName = reinterpret_cast<const char*>(fileData + nameOffset);

            WORD ordinal = ordinalTable[i];
            DWORD functionOffset = CPEAnalyzer::ConvertRVAtoFileOffset(functionRVAs[ordinal], fileData);
            BYTE* originalFunctionCode = fileData + functionOffset;

            // ����ת������
            if (CHookDetector::IsForwarderFunction(originalFunctionCode)) continue;

            FARPROC hookedFunction = ::GetProcAddress(loadedModule, functionName);
            if (!hookedFunction) continue;

            if (CHookDetector::IsFunctionHooked(originalFunctionCode, reinterpret_cast<BYTE*>(hookedFunction))) {
                if (RestoreFunctionCode(originalFunctionCode, hookedFunction, 16)) {
                    anyHooksFixed = true;
                }
            }
        }

        return anyHooksFixed;
    }

    static bool RestoreFunctionCode(const BYTE* originalCode, FARPROC hookedFunction, SIZE_T codeSize) {
        CMemoryProtector protector(hookedFunction, codeSize, PAGE_EXECUTE_READWRITE);
        if (!protector.IsSuccessful()) return false;

        // ��ȫ���ڴ渴��
        BYTE* destination = reinterpret_cast<BYTE*>(hookedFunction);
        for (SIZE_T i = 0; i < codeSize; ++i) {
            destination[i] = originalCode[i];
        }

        // ˢ��ָ���ȷ���޸���Ч
        ::FlushInstructionCache(::GetCurrentProcess(), hookedFunction, codeSize);
        return true;
    }
};

// �ַ���������Կ����
const BYTE CAntiHookEngine::CStringObfuscator::OBFUSCATION_KEYS[4] = { 0x7F, 0xA5, 0x3C, 0xE9 };

// ��ȫ�ֽӿ�
inline bool AntiHook_RemoveAllHooks() {
    return CAntiHookEngine::RemoveAllHooks();
}

inline bool AntiHook_RemoveModuleHooks(const char* moduleName) {
    return CAntiHookEngine::RemoveHooksForModule(moduleName);
}