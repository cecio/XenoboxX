#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <executable_path> [delay_in_seconds]\n", argv[0]);
        return 1;
    }

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Convert argv[1] to a wide string
    int size = MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, NULL, 0);
    wchar_t* wideExecutablePath = (wchar_t*)malloc(size * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, wideExecutablePath, size);


    // Start the child process in suspended mode
    if (!CreateProcess(NULL,   // No module name (use command line)
        wideExecutablePath,    // Command line
        NULL,                  // Process handle not inheritable
        NULL,                  // Thread handle not inheritable
        FALSE,                 // Set handle inheritance to FALSE
        CREATE_SUSPENDED,      // Creation flags - start suspended
        NULL,                  // Use parent's environment block
        NULL,                  // Use parent's starting directory 
        &si,                   // Pointer to STARTUPINFO structure
        &pi)                   // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return 1;
    }

    printf("Started process with PID: %lu (0x%x)\n", pi.dwProcessId, pi.dwProcessId);

    // If no additional argument is given, wait for a key press to resume
    if (argc == 2) {
        printf("Press enter key to resume the process.\n");
        getchar();
        ResumeThread(pi.hThread);
    }
    else {
        // Resume immediately and then suspend after given seconds
        ResumeThread(pi.hThread);
        int delay = atoi(argv[2]);
        Sleep(delay * 1000); // Convert to milliseconds
        SuspendThread(pi.hThread);
        printf("Process suspended. Press enter key to resume.\n");
        getchar();
        ResumeThread(pi.hThread);
    }

    // Close process and thread handles. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
