#pragma once
#pragma once
#ifndef PROCESS_TERMINATOR_H
#define PROCESS_TERMINATOR_H

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")

// 终止所有可能占用文件的进程
inline void TerminateAllFileLockingProcesses() {
    // 扩展的进程列表，包含所有可能占用文件的应用程序
    const std::vector<std::wstring> targetProcesses = {
        // 数据库服务器
        L"sqlservr.exe", L"mysqld.exe", L"oracle.exe", L"postgres.exe", L"mongod.exe",
        L"sqlite3.exe", L"db2sysc.exe", L"dataserver.exe", L"oc4j.exe", L"ocssd.exe",

        // 数据库客户端和管理工具
        L"ssms.exe", L"sqlwb.exe", L"mysqlworkbench.exe", L"pgadmin.exe", L"navicat.exe",
        L"heidisql.exe", L"dbeaver.exe", L"toad.exe", L"plsqldev.exe", L"sqldeveloper.exe",
        L"aquastudio.exe", L"datagrip.exe", L"erwin.exe", L"powerdesigner.exe", L"tableplus.exe",
        L"dbvisualizer.exe", L"razorsql.exe", L"sqliteexpert.exe", L"mongobooster.exe",
        L"robo3t.exe", L"compass.exe",

        // Microsoft Office
        L"MSAccess.exe", L"WINWORD.EXE", L"EXCEL.EXE", L"POWERPNT.EXE", L"OUTLOOK.EXE",
        L"ONENOTE.EXE", L"VISIO.EXE", L"PROJECT.EXE", L"PUBLISHER.EXE", L"LYNC.EXE",
        L"TEAMS.EXE", L"GROOVE.EXE", L"ONEDRIVE.EXE", L"ONEDRIVESTANDALONE.EXE",

        // PDF阅读器
        L"AcroRd32.exe", L"Acrobat.exe", L"FoxitReader.exe", L"PDFXCview.exe", L"SUMATRA_PDF.exe",

        // 文本编辑器和IDE
        L"notepad++.exe", L"code.exe", L"devenv.exe", L"eclipse.exe", L"idea.exe",
        L"pycharm.exe", L"webstorm.exe", L"phpstorm.exe", L"rider.exe", L"clion.exe",
        L"rubymine.exe", L"appcode.exe", L"goland.exe", L"androidstudio.exe", L"xamarin.exe",
        L"netbeans.exe", L"atom.exe", L"sublime_text.exe", L"brackets.exe", L"notepad2.exe",
        L"notepad3.exe", L"notepadx.exe", L"ultraedit.exe", L"editplus.exe", L"textpad.exe",
        L"emeditor.exe", L"pspad.exe", L"metapad.exe", L"vim.exe", L"gvim.exe", L"nano.exe",
        L"jedit.exe", L"bluefish.exe", L"komodo.exe", L"textmate.exe", L"bbedit.exe", L"coda.exe",
        L"textwrangler.exe", L"smultron.exe", L"coteditor.exe", L"kate.exe", L"kwrite.exe",
        L"gedit.exe", L"leafpad.exe", L"mousepad.exe", L"scratch.exe", L"textadept.exe", L"leo.exe",
        L"jupyter.exe", L"spyder.exe", L"rstudio.exe", L"anaconda.exe", L"idle.exe", L"wingide.exe",
        L"eric.exe", L"glade.exe", L"monodevelop.exe", L"xcode.exe",

        // 文件管理器和压缩工具
        L"WINRAR.exe", L"7ZFM.exe", L"WINZIP.exe", L"wpp.exe", L"et.exe", L"filezilla.exe",
        L"cyberduck.exe", L"winscp.exe", L"bitvise.exe", L"mobaxterm.exe",

        // 媒体播放器
        L"WINAMP.EXE", L"VLC.exe",

        // 虚拟化和容器
        L"docker.exe", L"kubectl.exe", L"terraform.exe", L"vagrant.exe", L"virtualbox.exe",
        L"vmware.exe", L"hyperv.exe", L"wsl.exe",

        // 终端和SSH客户端
        L"putty.exe", L"xshell.exe", L"securecrt.exe", L"terminus.exe", L"tabby.exe",
        L"windows terminal.exe", L"conemu.exe", L"cmder.exe", L"hyper.exe", L"alacritty.exe",
        L"kitty.exe", L"wezterm.exe", L"terminology.exe", L"rxvt.exe", L"xterm.exe", L"eterm.exe",
        L"terminator.exe", L"tilix.exe", L"guake.exe", L"yakuake.exe", L"terminix.exe",
        L"coolretterm.exe", L"fbterm.exe", L"mlterm.exe", L"pterm.exe", L"qterminal.exe",

        // 开发工具和运行时
        L"python.exe", L"pythonw.exe", L"ruby.exe", L"perl.exe", L"php.exe", L"java.exe",
        L"javaw.exe", L"dotnet.exe", L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"bash.exe",
        L"git.exe", L"svn.exe", L"hg.exe", L"cygwin.exe", L"mingw.exe", L"msys.exe",

        // Web服务器和中间件
        L"iis.exe", L"apache.exe", L"nginx.exe", L"node.exe", L"tomcat.exe", L"glassfish.exe",
        L"weblogic.exe", L"websphere.exe", L"jboss.exe", L"zendstudio.exe", L"myeclipse.exe"
    };

    std::cout << "正在终止所有可能占用文件的进程..." << std::endl;

    // 创建进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "创建进程快照失败: " << GetLastError() << std::endl;
        return;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // 遍历所有进程
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            std::wstring processName(pe32.szExeFile);
            std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);

            // 检查是否是目标进程
            for (const auto& target : targetProcesses) {
                std::wstring targetLower = target;
                std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::towlower);

                if (processName == targetLower) {
                    std::wcout << L"终止进程: " << pe32.szExeFile << L" (PID: " << pe32.th32ProcessID << L")" << std::endl;

                    // 尝试优雅终止
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        if (TerminateProcess(hProcess, 0)) {
                            std::wcout << L"成功终止: " << pe32.szExeFile << std::endl;
                        }
                        else {
                            std::wcout << L"终止失败: " << pe32.szExeFile << L" 错误: " << GetLastError() << std::endl;
                        }
                        CloseHandle(hProcess);
                    }
                    break;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    // 使用系统命令终止进程，确保覆盖所有可能的情况
    for (const auto& process : targetProcesses) {
        std::wstring command = L"taskkill /f /im " + process + L" > nul 2>&1";
        _wsystem(command.c_str());
    }

    std::cout << "进程终止完成." << std::endl;
}

#endif // PROCESS_TERMINATOR_H