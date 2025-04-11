#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <windows.h>

namespace Payload {
    
    struct PayloadData {
        unsigned char* code;
        SIZE_T codeSize;
        const char* message;
        const char* title;
    };

    PayloadData GetDefaultPayload();

    BOOL InjectPayload(HANDLE hProcess, const PayloadData& payload, LPVOID* remoteBuffer);

} 

#endif 