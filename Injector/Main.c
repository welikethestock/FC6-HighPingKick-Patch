#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <TlHelp32.h>

DWORD FindPID(const char *Executable)
{
    PROCESSENTRY32 Entry;
    Entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (!Process32First(Snapshot, &Entry))
    {
        CloseHandle(Snapshot);

        return NULL;
    }

    while (Process32Next(Snapshot, &Entry))
    {
        if (stricmp(Entry.szExeFile, Executable) == 0)
        {
            CloseHandle(Snapshot);

            return Entry.th32ProcessID;
        }
    }

    CloseHandle(Snapshot);

    return NULL;
}

#define PATCH_FILE      "Patch.dll"
#define GAME_EXECUTABLE "FarCry6.exe"

int ExitWithMessage(const char *Message)
{
    printf(Message);

    return getchar();
}

int main()
{
    void *LoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    printf("Waiting for game...\n");

    DWORD ProcessID = NULL;
    do
    {
        ProcessID = FindPID(GAME_EXECUTABLE);

        Sleep(1);
    } while (ProcessID == NULL);

    printf("Found game (pid %d)\n", ProcessID);

    HANDLE Process = OpenProcess(STANDARD_RIGHTS_REQUIRED | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, ProcessID);
    if (Process == NULL)
    {
        return ExitWithMessage("OpenProcess failed\n");
    }

    printf("OpenProcess successful (handle %p)\n", Process);

    void *Memory = VirtualAllocEx(Process, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (Memory == NULL)
    {
        return ExitWithMessage("VirtualAllocEx failed\n");
    }

    printf("VirtualAllocEx successful (address %p)\n", Memory);

    if (!WriteProcessMemory(Process, Memory, PATCH_FILE, strlen(PATCH_FILE) + 1, NULL))
    {
        return ExitWithMessage("WriteProcessMemory failed\n");
    }

    printf("WriteProcessMemory successful\n");

    HANDLE Thread = CreateRemoteThread(Process, NULL, NULL, LoadLibraryA, Memory, NULL, NULL);
    if (Thread == NULL)
    {
        return ExitWithMessage("CreateRemoteThread failed\n");
    }

    printf("CreateRemoteThread successful\nWaiting for thread to finish...\n");
    WaitForSingleObject(Thread, INFINITE);

    CloseHandle(Thread);
    VirtualFreeEx(Process, Memory, 0, MEM_RELEASE);
    CloseHandle(Process);

    return ExitWithMessage("Injected successfully\n");
}