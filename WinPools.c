#include <stdio.h>
#include <windows.h>

// Source of structs: http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool_entry.htm
typedef struct _SYSTEM_BIGPOOL_ENTRY {
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    ULONG_PTR SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagULong;
    };
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count; 
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

// Source of enum http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm?tx=53&ts=0,16.66666603088379
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBigPoolInformation = 0x42
} SYSTEM_INFORMATION_CLASS;
typedef NTSTATUS (WINAPI *fNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
                                                    ULONG SystemInformationLength, PULONG ReturnLength);

int main(int argc, char* argv[]) { 
    printf("WinPools - An example program which leaks kernel big pool information\n");
    printf("Big Pool = Pools >= 0xFF (4080)\n");
    printf("----------------------------------------------------------------\n"); // End of intro information
    HANDLE hNtdll = LoadLibraryA("ntdll.dll"); // Load ntdll (99.99% of the time it is already is loaded)
    if (hNtdll == INVALID_HANDLE_VALUE) {
        printf("[!!!] Unable to load ntdll.dll\n");
        ExitProcess(-1);
    }
    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation == 0) {
    printf("[!!!] Unable to find NtQuerySystemInformation\n");
        ExitProcess(-1);
    }
    printf("[i] Allocating a heap\n");
    LPVOID lpHeap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0);
    if (lpHeap == 0) {
    printf("[!!!] Unable to allocate a heap\n");
        ExitProcess(-1);
    }
    printf("[i] Gathering initial statistics\n");
    DWORD dwOutLength = 0;
    DWORD dwCurrentSize = 0;
    lpHeap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lpHeap, 0xFF);
    NTSTATUS ntLastStatus = NtQuerySystemInformation(SystemBigPoolInformation, lpHeap, 0x30, &dwOutLength); // 0x30 is smallest size you can use to get accurate output for length
    printf("[i] NTSTATUS: %I64X Required Size of heap: %I64X\n", ntLastStatus, dwOutLength);
    lpHeap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lpHeap, dwOutLength + 0x1F); // Size changes rapidly, better to have extra space
    dwCurrentSize = dwOutLength;
    ntLastStatus = NtQuerySystemInformation(SystemBigPoolInformation, lpHeap, dwCurrentSize, &dwOutLength); // Real call
    printf("[i] NTSTATUS: %I64X\n", ntLastStatus);
    PSYSTEM_BIGPOOL_INFORMATION pSystemBigPoolInfo = lpHeap; 
    printf("Number of big pools: %d\n", pSystemBigPoolInfo->Count);
    PSYSTEM_BIGPOOL_ENTRY pCurrentBigPoolEntry = pSystemBigPoolInfo->AllocatedInfo;
    DWORD dwNumberWritten = 0;
    for (int i = 0; i < pSystemBigPoolInfo->Count; i++) {
    printf("Tag: %.4s | VA: 0x%I64X | Size (Bytes): 0x%I64X\n", pCurrentBigPoolEntry->Tag, pCurrentBigPoolEntry->VirtualAddress, pCurrentBigPoolEntry->SizeInBytes); // Only print 4 chars. Pool Tags are always 4 chars
        pCurrentBigPoolEntry++; // Next entry in SYSTEM_BIGPOOL_INFORMATION
    }
    printf("\nFinal Stats: \n");
    printf("Total Pools with tags: %d\n", pSystemBigPoolInfo->Count);
    HeapFree(GetProcessHeap(), 0, lpHeap);		
    printf("[NOTE] Kernel pools are constantly being allocated and freed. Results are not 100%% accurate.\n"); // Warning notice
    ExitProcess(0); // Exit program
} 
