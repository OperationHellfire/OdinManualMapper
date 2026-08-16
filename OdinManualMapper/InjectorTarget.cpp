#include "InjectorTarget.h"

DWORD InjectorTarget::GetProcessByName(const wchar_t* processName) {
	DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(processEntry);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (wcscmp(processName, processEntry.szExeFile) == 0) {
                pid = processEntry.th32ProcessID;
                break; 
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return pid;
}