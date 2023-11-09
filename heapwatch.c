#include <Windows.h>
#include <wchar.h>
#include <tlhelp32.h>
#include <errno.h>

/*
    HeapWatch - Dynamic memory process control block heap block allocation viewer.

    Enables the basic feature set of viewing the current Process Control Block structure field members
    pertaining to the information stored in the target processes virtual memory space by viewing the currently
    allotted heap structure control blocks (heap blocks allocated within the VMA space of the target executable once it has been loaded into memory) 
*/

#define MAX_BOUNDS_DEPTH "\t____________________________________________________________\n"

void peekOverHeapList(DWORD procPID);
PROCESSENTRY32 QueryProcInfo(DWORD pid); // function to return handle to target process ID
LPWSTR returnMsgBuffer(DWORD errorCode);


int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("## ERROR => You have failed to specify the target process ID!\n", NULL);
        exit(1);
    }

    int cast_pid = atoi(argv[1]); DWORD pid = (DWORD)cast_pid;

    printf("\033[0;34m[*]\033[0;m TARGET_PID => %d\n\t++ Starting process heap enumeration for target PID\n", pid);

    peekOverHeapList(pid);

    return 0;
}


void peekOverHeapList(DWORD procPID)
{
    printf("\t++ Attempting to obtain a peek on SNAPHEAPLIST for target process (%d)\n\n", procPID);

    // obtain a system snapshot of the target process
    HANDLE pHeapSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, procPID);
    
    if (pHeapSnapshot == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();
        PROCESSENTRY32 procNameExe = QueryProcInfo(procPID);

        wprintf(L"\nFailed to obtain a handle (snapshot) of the target process \"%hs\"\n## Error: %s\n", procNameExe.szExeFile, returnMsgBuffer(error));

        exit(1);
    }

    printf("\t++ Snapshot of current system processes created. Loading proper HEAPLIST32 structure in memory\n", NULL);

    // initialize an entry structure for the target process's heap
    HEAPLIST32 pHeapList = {sizeof(HEAPLIST32), 0};

    if (Heap32ListFirst(pHeapSnapshot, &pHeapList))
    {
        printf("\t++ HEAPLIST32 structure created at memory address: 0x%0x\n\n", &pHeapList);
        printf("\t## Heap list snapshot in memory successfully created. Main execution dormant 3 seconds to display advanced information...\n\n", NULL);
        
        Sleep(3000);

        printf("%s", MAX_BOUNDS_DEPTH);

        do 
        {
            DWORD processID = pHeapList.th32ProcessID;
            ULONG_PTR pth32HeapID = pHeapList.th32HeapID;

            HEAPENTRY32 pHeapEntry32 = {sizeof(HEAPENTRY32), 0};

            // Get the next memory block that is stored within the region of memory in the heap
            if (Heap32First(&pHeapEntry32, processID, pth32HeapID))
            {
                do 
                {
                    printf("\t\t%% Heap block size => %lu bytes\n", pHeapEntry32.dwBlockSize);
                    printf("\t\t%% Heap Lock Count => %d\n", pHeapEntry32.dwLockCount);
                    printf("\t\t%% Heap blocks (resvd) => %lu\n", pHeapEntry32.dwResvd);
                    printf("\t\t%% \"Start of Block\" Address => 0x%0x\n", pHeapEntry32.dwAddress);
                    printf("\t\t%% Heap Identifier => %lu\n", pHeapEntry32.th32HeapID);

                    // HeapID = this field identifies the heap to which the memory block belongs, this
                    // is pretty much a tag/identifier ID for this block of memory allocated by the dynamic memory (heap) allocator for the current PCB (Process Control Block)

                    printf("%s", MAX_BOUNDS_DEPTH);

                } while (Heap32Next(&pHeapEntry32));
            }

        // while there is a valid memory block associated with a heap ID, continue...
        } while (Heap32ListNext(pHeapSnapshot, &pHeapList));
    }

    // target process executable name, returns 
    wchar_t *procNameExe = QueryProcInfo(procPID).szExeFile;
    CloseHandle(pHeapSnapshot);

    printf("\n## END OF HEAP LISTING FOR TARGET PROCESS: \"%hs\" ...\033[0;32mDONE\033[0;m\n", procNameExe);
}


// obtain a valid process control block structure from the operating system
// via win32 api system calls (CPU trap/return from trap instructions)
PROCESSENTRY32 QueryProcInfo(DWORD pid)
{
    PROCESSENTRY32 procEntry32 = {0};
    procEntry32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE p32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (p32Snapshot == INVALID_HANDLE_VALUE)
    {
        printf("!! Failed to obtain a handle to the target process for PCB name structure field enumeration!\n", NULL);

        // return empty struct, as no data was found
        return procEntry32;
    }
    else 
    {
        if (Process32First(p32Snapshot, &procEntry32))
        {
            do
            {
                if (procEntry32.th32ProcessID == pid)
                {
                    CloseHandle(p32Snapshot);

                    return procEntry32;
                }

            // continue looping while another process block entry (field member) exists for another heap block identifier
            // whithin the current process entry structure
            } while (Process32Next(p32Snapshot, &procEntry32));
        }
    }

    // free target process snapshot handle, return resources to OS
    CloseHandle(p32Snapshot);

    // return the Process Control Block structure
    return procEntry32;
}


LPWSTR returnMsgBuffer(DWORD errorCode)
{
    LPWSTR msgBuffer = NULL;

    DWORD result = FormatMessageW
    (
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&msgBuffer,
        0,
        NULL
    );

    return msgBuffer;
}