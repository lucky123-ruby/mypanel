#pragma once
#pragma once
// SecurityChecks.cpp
#include <windows.h>
#include <lm.h>
#include <wtsapi32.h>
#include <iostream>

bool DetectSecurityProcesses() {
    // 简化的安全进程检测逻辑
    const wchar_t* processes[] = {
        L"MsMpEng.exe", L"McAfee", L"Symantec",
        L"bdagent.exe", L"avp.exe", L"SBAMSvc.exe"
    };

    for (const auto& proc : processes) {
        if (FindWindowW(NULL, proc) || GetModuleHandleW(proc)) {
            return true;
        }
    }
    return false;
}

bool IsEnterpriseEdition() {
    OSVERSIONINFOEX osvi = { sizeof(OSVERSIONINFOEX) };
    GetVersionEx((LPOSVERSIONINFO)&osvi);
    return (osvi.wProductType == VER_NT_WORKSTATION &&
        osvi.wSuiteMask & VER_SUITE_ENTERPRISE);
}

bool IsDomainJoined() {
    LPWSTR domainName;
    NETSETUP_JOIN_STATUS status;
    if (NetGetJoinInformation(NULL, &domainName, &status) == NERR_Success) {
        NetApiBufferFree(domainName);
        return (status == NetSetupDomainName);
    }
    return false;
}