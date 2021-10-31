#include <stdio.h>
#include "windowsMod.h"

// Registry Most Common Actions
BOOL InstallRegistryAutoRunKey(wchar_t* key_name, wchar_t* key_value) {
    DWORD cbData = (strlen(key_value) + 1) * sizeof(wchar_t);
    HKEY AutoRunKey;
    LSTATUS ret;
    wchar_t autoRunPath[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    ret = RegOpenKeyEx(HKEY_CURRENT_USER, autoRunPath, 0, KEY_SET_VALUE, &AutoRunKey);
    if (ret != ERROR_SUCCESS) {
        printf("[-] Error while opening key : %ld\n", ret);
        return FALSE;
    }
    ret = RegSetValueEx(AutoRunKey, key_name, 0, REG_SZ, (const BYTE*)key_value, cbData);
    if (ret != ERROR_SUCCESS) {
        printf("[-] Error while opening key : 0x%ld\n", ret);
        return FALSE;
    }
    return TRUE;
}
BOOL RemoveRegistryAutoRunKey(char* key_name) {
    HKEY AutoRunKey;
    LSTATUS ret;
    char autoRunPath[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    ret = RegOpenKeyEx(HKEY_CURRENT_USER, autoRunPath, 0, KEY_SET_VALUE, &AutoRunKey);
    if (ret != ERROR_SUCCESS) {
        printf("[-] Error while opening key : %ld\n", ret);
        return FALSE;
    }
    ret = RegDeleteValueA(AutoRunKey, key_name);
    if (ret != ERROR_SUCCESS) {
        printf("[-] Error while deleting key : 0x%ld\n", ret);
        return FALSE;
    }
    return TRUE;
}

// Processes
void ListProcesses() {
    HANDLE ToolHelp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 ProcessInfo;
    ProcessInfo.dwSize = sizeof(PROCESSENTRY32);

    Process32First(ToolHelp, &ProcessInfo);
    do {
        printf("[ %ls PID: %lu PPID: %lu ]\n", ProcessInfo.szExeFile, ProcessInfo.th32ProcessID, ProcessInfo.th32ParentProcessID);
    } while (Process32Next(ToolHelp, &ProcessInfo));
}
DWORD GetProcessIdByName(wchar_t* ProcessName) {
    HANDLE ToolHelp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 ProcessInfo;
    ProcessInfo.dwSize = sizeof(PROCESSENTRY32);
    Process32First(ToolHelp, &ProcessInfo);
    wchar_t process_name[260];
    do {
        wcscpy_s(process_name, 260, ProcessInfo.szExeFile);
        if (!wcscmp(process_name, ProcessName)) {
            return ProcessInfo.th32ProcessID;
        }
    } while (Process32Next(ToolHelp, &ProcessInfo));

    return INVALID_PROCESS_ID;
}
HANDLE GetProcessHandleByName(wchar_t* ProcessName, DWORD dwProcessDesiredAccess, BOOL inheritedHandles) {
    DWORD PID = GetProcessIdByName(ProcessName);
    HANDLE pHandle = NULL;
    if (PID != INVALID_PROCESS_ID) {
        pHandle = OpenProcess(dwProcessDesiredAccess, inheritedHandles, PID);
        if (pHandle != NULL) {
            return pHandle;
        }
        else {
            printf("[-] Error while accessing process with pid %lu : %lu\n", PID, GetLastError());
            return NULL;
        }
    }
    else {
        printf("[-] Could not found process with name : %s\n", ProcessName);
        return NULL;
    }

}
DWORD CreateProcessWithParent(DWORD ParentProcessID, wchar_t * NewProcessName) {
	HANDLE hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ParentProcessID);
	BOOL ret = FALSE;
	SIZE_T ProcThreadAttrSize = 0;

	if (!hParentProcess) {
        printf("[-] Error while opening parent process : %lu\n", GetLastError());
		return FALSE;
	}

	// Receive buffer size first
	InitializeProcThreadAttributeList(NULL, 1, 0, &ProcThreadAttrSize);

	PPROC_THREAD_ATTRIBUTE_LIST AttList = (PPROC_THREAD_ATTRIBUTE_LIST)calloc(1, ProcThreadAttrSize);

	ret =  InitializeProcThreadAttributeList(AttList, 1, 0, &ProcThreadAttrSize);
	if (!ret) {
		printf("[-] Error initializing thread attribute list\n");
		return FALSE;
	}

	ret = UpdateProcThreadAttribute(AttList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(hParentProcess), NULL, NULL);
	if (!ret) {
		printf("[-] Error updating thread attribute list\n");
		return FALSE;
	}


	PROCESS_INFORMATION NewProcInfo;
	STARTUPINFOEX NewProcStartupInfoEx;
    ZeroMemory(&NewProcStartupInfoEx, sizeof(STARTUPINFOEX));
    GetStartupInfo(&NewProcStartupInfoEx.StartupInfo);
	NewProcStartupInfoEx.StartupInfo.cb = sizeof(STARTUPINFOEX);
	NewProcStartupInfoEx.lpAttributeList = AttList;

	ret = CreateProcessW(NULL, NewProcessName, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &NewProcStartupInfoEx, &NewProcInfo);
	if (!ret) {
		printf("[-] Error creating process : %lu\n", GetLastError());
		return FALSE;
	}

	printf("[+] Process created with PID = %lu\n", NewProcInfo.dwProcessId);
    WaitForSingleObject(NewProcInfo.hProcess, INFINITE);
	CloseHandle(NewProcInfo.hProcess);
	CloseHandle(NewProcInfo.hThread);
	CloseHandle(hParentProcess);
	DeleteProcThreadAttributeList(AttList);
	free(AttList);
	return NewProcInfo.dwProcessId;
}
BOOL ChangeProcessPriority(DWORD dwProcessID, DWORD dwPriority) {
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, dwProcessID);
    if (!hProcess) {
        printf("[-] Error changing process priority : %lu\n", GetLastError());
        return FALSE;
    }
    

    // According to Windows 10 System Programming by Pavel Yosifovich
    // this is the priority table
    // 4 - Idle Priority
    // 6 - Below Normal Priority
    // 8 - Normal Priority
    // 10 - Above normal priority
    // 13 - High priority
    // 24 - Real time priority (require priveleges)
    switch (dwPriority) {
        case 4:
            dwPriority = IDLE_PRIORITY_CLASS;
            break;
        case 6:
            dwPriority = BELOW_NORMAL_PRIORITY_CLASS;
            break;
        case 10:
            dwPriority = ABOVE_NORMAL_PRIORITY_CLASS;
            break;
        case 13:
            dwPriority = HIGH_PRIORITY_CLASS;
            break;
        case 24:
            dwPriority = REALTIME_PRIORITY_CLASS;
            break;
        default:
            dwPriority = NORMAL_PRIORITY_CLASS;
    }

    return SetPriorityClass(hProcess, dwPriority);
}
BOOL SetProcessState(DWORD dwProcessId, DWORD ProcessState) {
    HANDLE hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 ThreadEntry;
    ThreadEntry.dwSize = sizeof(THREADENTRY32);

    Thread32First(hProcSnapshot, &ThreadEntry);

    // Searching for threads
    HANDLE hThread = NULL;
    do {
        if (ThreadEntry.th32OwnerProcessID == dwProcessId) {
            hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ThreadEntry.th32ThreadID);
            if (!hThread) {
                return FALSE;
            }

            if (ProcessState == PROCESS_STATE_RESUME) {
                ResumeThread(hThread);
            }
            else if (ProcessState == PROCESS_STATE_SUSPEND) {
                SuspendThread(hThread);
            }
            hThread = NULL;
        }
    } while (Thread32Next(hProcSnapshot, &ThreadEntry));
}






