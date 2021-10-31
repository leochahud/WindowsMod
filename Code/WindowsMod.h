#ifndef WINDOWSMOD_H
#define WINDOWSMOD_H

#include <windows.h>
#include <tlhelp32.h>

// Windows processes are always multiples of 4, so we set INVALID_PROCESS_ID to 3
#define INVALID_PROCESS_ID 3

#define PROCESS_STATE_SUSPEND 0
#define PROCESS_STATE_RESUME 1


BOOL InstallRegistryAutoRunKey(wchar_t* key_name, wchar_t* key_value);
BOOL RemoveRegistryAutoRunKey(char* key_name);

// Processes
void ListProcesses();
BOOL ChangeProcessPriority(DWORD dwProcessID, DWORD dwPriority);
HANDLE GetProcessHandleByName(wchar_t* ProcessName, DWORD dwProcessDesiredAccess, BOOL inheritedHandles);
DWORD CreateProcessWithParent(DWORD ParentProcessID, wchar_t* NewProcessName);
DWORD GetProcessIdByName(wchar_t* ProcessName);
BOOL SetProcessState(DWORD dwProcessId, DWORD ProcessState);

#endif
