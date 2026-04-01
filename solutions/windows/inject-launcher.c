#include <stdio.h>
#include <Windows.h>

// this lancher injects the malicious code before the admin process runs
// if you use this you might need to adjust the paths
// it was compiled with : gcc -o inject-launcher inject-launcher.c

// Constants
static const char* main_path = "D:\\Cyber\\hack-challenge\\main-windows.exe";
static const char* dll_path = "D:\\Cyber\\hack-challenge\\solutions\\windows\\windows-injector.dll";

int main() {
    printf("Launching...\n");

    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
    STARTUPINFOA startup_info = { .cb = sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION process_info;

    // this creates the admin process
    BOOL process_created = CreateProcessA(
        main_path,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_SUSPENDED, // creates the process with a suspended state, this gives us the time to inject the dll
        NULL,
        NULL,
        &startup_info,
        &process_info
    );

    if (process_created == FALSE) {
        printf("Failed to create process, error code: %llu\n", GetLastError());
        return -1;
    }

    SIZE_T dll_path_length = strlen(dll_path) + 1;

    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    // for allocating memory inside the admin process
    LPVOID injected_dll_path = VirtualAllocEx(
        process_info.hProcess,
        NULL,
        dll_path_length,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (injected_dll_path == NULL) {
        printf("Failed to allocate memory, error code: %llu\n", GetLastError());
        return -1;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    BOOL memory_written = WriteProcessMemory(
        process_info.hProcess,
        injected_dll_path,
        dll_path,
        dll_path_length,
        NULL
    );

    if (memory_written == FALSE) {
        printf("Failed to write memory into process, error code: %llu\n", GetLastError());
        return -1;
    }

    // next we need to start a thread inside the admin process, which will perform the dll injection.
    // every windows process has access to the kernel32 dll, which provides a function for loading a dll into a process (LoadLibraryA)
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
    // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya

    HMODULE kernel_module = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE dll_loader = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel_module, "LoadLibraryA");

    // now that we have the loader we can launch a thread and tell it to inject the malicious code
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    HANDLE inject_thread = CreateRemoteThread(
        process_info.hProcess,
        NULL,
        0,
        dll_loader,
        injected_dll_path,
        0,
        NULL
    );

    WaitForSingleObject(inject_thread, INFINITE); // blocks the launcher until the dll is fully injected

    ResumeThread(process_info.hThread);

    CloseHandle(inject_thread);
    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);

    printf("Launch complete\n");

    return 0;
}