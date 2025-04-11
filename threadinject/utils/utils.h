#ifndef PROCESS_UTILS_H
#define PROCESS_UTILS_H

#include <windows.h>
#include <string>

namespace ProcessUtils {
	DWORD GetProcessIdByName(const std::wstring& processName);

	HANDLE OpenProcessById(DWORD processId, DWORD access);

} 

#endif 