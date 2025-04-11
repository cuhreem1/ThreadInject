#include "utils.h"
#include <tlhelp32.h>
#include <iostream>

namespace ProcessUtils {

    DWORD GetProcessIdByName(const std::wstring& processName) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create snapshot: " << GetLastError() << std::endl;
            return 0;
        }

        PROCESSENTRY32W pe32 = { sizeof(pe32) };
        DWORD pid = 0;

        if (Process32FirstW(snapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe32));
        }

        CloseHandle(snapshot);
        return pid;
    }

    HANDLE OpenProcessById(DWORD processId, DWORD access) {
        HANDLE hProcess = OpenProcess(access, FALSE, processId);
        if (hProcess == NULL) {
            std::cerr << "Failed to open process: " << GetLastError() << std::endl;
        }
        return hProcess;
    }

} 