// wx64_dumpalloc.c :
// Compatible with Windows x64.
//
// Monitor memory allocations of a given process and dumps them
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_dumpalloc.c
// ml64.exe wx64_common_a.asm /Fewx64_dumpalloc.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_dumpalloc.obj wx64_common.obj
// shellcode64.exe -o wx64_dumpalloc.exe "DUMP ALLOCATED MEMORY                                \n===============================================================\nREQUIRED OPTIONS:                                              \n  -0   : Process PID to open. Example '-0 0x0fe0'.        \nOPTIONAL OPTIONS:                                              \n  -1   : Process monitoring timeout Default: 0x20. Example:  '-1 0x100'. \n  -s   : Specify output folder/file for dumps. Example: \"\\??\C:\temp\test\"\n===== RESULT OF DUMPALLOC OPERATION ======================%s\nNTSTATUS  : 0x%08X                                             \n===============================================================\n"
//
// sudo ./pcileech wx64_dumpalloc -0 0xbac -s "\\??\C:\temp\test" -kmd 0x7ffff000
//

#include "wx64_common.h"

#define STATUS_UNSUCCESSFUL                    0xC0000001
#define STATUS_ACCESS_DENIED                   0xC0000022
#define OBJ_CASE_INSENSITIVE                   0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT           0x00000020
#define FILE_OVERWRITE_IF                      0x00000005
#define OBJ_KERNEL_HANDLE                      0x00000200

#define DPFLTR_IHVDRIVER_ID                    77
#define DPFLTR_INFO_LEVEL                       3
#define DPFLTR_TRACE_LEVEL                      2
#define DPFLTR_WARNING_LEVEL                    1
#define DPFLTR_ERROR_LEVEL                      0

#define MAX_OUTSTRING                          64

//----------------------------------------------------------------------------------------------------------
// Section for the File Output

HANDLE hFile;
IO_STATUS_BLOCK _io;
// File sequence counter
SIZE_T fileSeq;

//----------------------------------------------------------------------------------------------------------
// Section for Dumping memory

typedef struct _OBJECT_TYPE *POBJECT_TYPE;

typedef struct _OBJECT_HANDLE_INFORMATION {
    ULONG HandleAttributes;
    ACCESS_MASK GrantedAccess;
} OBJECT_HANDLE_INFORMATION, *POBJECT_HANDLE_INFORMATION;

//----------------------------------------------------------------------------------------------------------
// Section for memory region inspection

#define MAX_REGIONS                         1024

typedef struct _MEMORY_REGION_INFO {
    QWORD BaseAddress;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
} MEMORY_REGION_INFO, *PMEMORY_REGION_INFO;

MEMORY_REGION_INFO regions[MAX_REGIONS];
QWORD lastRegionUsed;

//----------------------------------------------------------------------------------------------------------
// Section for the Open Process

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

// https://asecuritysite.com/hash/ror13_2
#define H_ZwClose                               0x5d044c61
#define H_ZwOpenProcess                         0xf0d09d60
#define H_ZwTerminateProcess                    0x792cbc53
#define H_ZwQueryVirtualMemory                  0x4FD39C92
#define H_KeQuerySystemTimePrecise              0x0919E157
#define H_ObReferenceObjectByHandle             0xA7048186
#define H_MmCopyVirtualMemory                   0x8520E173
#define H_PsGetCurrentProcess                   0x8F8F1B7E
#define H_DbgPrintEx                            0x4170DA92
#define H_RtlAppendStringToString               0xD73BF388

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef struct tdKERNEL_FUNCTIONS2 {
    NTSTATUS(*ZwClose)(
        _In_ HANDLE Handle
    );
    NTSTATUS(*ZwOpenProcess)(
        _Out_    PHANDLE                        ProcessHandle,
        _In_     ACCESS_MASK                    DesiredAccess,
        _In_     POBJECT_ATTRIBUTES             ObjectAttributes,
        _In_opt_ PCLIENT_ID                     ClientId
    );
    NTSTATUS(*ZwTerminateProcess)(
        _In_opt_ HANDLE   ProcessHandle,
        _In_     NTSTATUS ExitStatus
    );
    NTSTATUS(*ZwQueryVirtualMemory)(
        _In_     HANDLE                         ProcessHandle,
        _In_opt_ PVOID                          BaseAddress,
        _In_     MEMORY_INFORMATION_CLASS       MemoryInformationClass,
        _Out_    PVOID                          MemoryInformation,
        _In_     SIZE_T                         MemoryInformationLength,
        _Out_opt_ PSIZE_T                       ReturnLength
    );
    VOID(*KeQuerySystemTimePrecise)(
        _Out_    PLARGE_INTEGER                 CurrentTime
    );
    NTSTATUS (*ObReferenceObjectByHandle)(
        _In_      HANDLE                        Handle,
        _In_      ACCESS_MASK                   DesiredAccess,
        _In_opt_  POBJECT_TYPE                  ObjectType,
        _In_      KPROCESSOR_MODE               AccessMode,
        _Out_     PVOID                         *Object,
        _Out_opt_ POBJECT_HANDLE_INFORMATION    HandleInformation
    );
    VOID (*ObDereferenceObject)(
        _In_      PVOID                         Object
    );
    NTSTATUS (*MmCopyVirtualMemory)(
        _In_      PEPROCESS                     SourceProcess,
        _In_      PVOID                         SourceAddress,
        _In_      PEPROCESS                     TargetProcess,
        _Out_     PVOID                         TargetAddress,
        _In_      SIZE_T                        BufferSize,
        _In_      KPROCESSOR_MODE               PreviousMode,
        _Out_     PSIZE_T                       ReturnSize
    );
    PEPROCESS (*PsGetCurrentProcess)(
    );
    ULONG (*DbgPrintEx)(
        _In_      ULONG                         ComponentId,
        _In_      ULONG                         Level,
        _In_      PCSTR                         Format,
        ...
    );
    NTSTATUS (*RtlAppendStringToString)(
        _Inout_   PANSI_STRING                  Destination,
        _In_      ANSI_STRING                   *Source
    );
} KERNEL_FUNCTIONS2, *PKERNEL_FUNCTIONS2;

VOID InitializeKernelFunctions2(_In_ QWORD qwNtosBase, _Out_ PKERNEL_FUNCTIONS2 fnk2)
{
    QWORD FUNC2[][2] = {
        { &fnk2->ZwClose,                           H_ZwClose },
        { &fnk2->ZwOpenProcess,                     H_ZwOpenProcess },
        { &fnk2->ZwTerminateProcess,                H_ZwTerminateProcess },
        { &fnk2->ZwQueryVirtualMemory,              H_ZwQueryVirtualMemory },
        { &fnk2->KeQuerySystemTimePrecise,          H_KeQuerySystemTimePrecise },
        { &fnk2->ObReferenceObjectByHandle,         H_ObReferenceObjectByHandle },
        { &fnk2->ObDereferenceObject,               H_ObDereferenceObject},
        { &fnk2->MmCopyVirtualMemory,               H_MmCopyVirtualMemory},
        { &fnk2->PsGetCurrentProcess,               H_PsGetCurrentProcess},
        { &fnk2->DbgPrintEx,                        H_DbgPrintEx},                  // TODO: Evaluate if should be kept
        { &fnk2->RtlAppendStringToString,           H_RtlAppendStringToString},     // TODO: Evaluate if should be kept
    };
    for(QWORD j = 0; j < (sizeof(FUNC2) / sizeof(QWORD[2])); j++) {
        *(PQWORD)FUNC2[j][0] = PEGetProcAddressH(qwNtosBase, (DWORD)FUNC2[j][1]);
    }
}

KERNEL_FUNCTIONS fnk;
KERNEL_FUNCTIONS2 fnk2;

//----------------------------------------------------------------------------------------------------------

VOID PointerToHexString(PVOID ptr, char* hexString) {

    // Dereference ptr to get the value
    unsigned long long address;
    unsigned long long* pAddress = (unsigned long long*)ptr;
    address = *pAddress;

    CHAR symbols[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    for (int i = 0; i < sizeof(PVOID) * 2; i++) {
        // Extract each 4-bit part of the address from the beginning to the end
        // Shift right by 4 * (15 - i) to get the next 4 bits
        int value = (address >> (4 * ((sizeof(PVOID) * 2 - 1) - i))) & 0xF;
        // Convert it to a hexadecimal digit
        hexString[i] = symbols[value];
    }

    // Null-terminate the string
    hexString[sizeof(PVOID) * 2] = '\0';
}

VOID IntegerToHexString(SIZE_T number, char* hexString) {
    char symbols[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    // Process the SIZE_T in 4-bit chunks
    for (int i = 0; i < sizeof(SIZE_T) * 2; i++) {
        // Extract each 4-bit part of the SIZE_T from the end to the beginning
        int value = (number >> (4 * (sizeof(SIZE_T) * 2 - 1 - i))) & 0xF;
        // Convert it to a hexadecimal digit
        hexString[i] = symbols[value];
    }

    // Null-terminate the string
    hexString[sizeof(SIZE_T) * 2] = '\0';
}

NTSTATUS HandleToPEPROCESS(HANDLE ProcessHandle, PEPROCESS *Process)
{
    NTSTATUS status;

    if (ProcessHandle == NULL || Process == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = fnk2.ObReferenceObjectByHandle(ProcessHandle,
                                            PROCESS_ALL_ACCESS,
                                            NULL,                    // May be a good idea to set to PsProcessType
                                            KernelMode,
                                            (PVOID*)Process,
                                            NULL);

    if (!NT_SUCCESS(status)) {
        // Handle conversion failed
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS ReadRegion(PEPROCESS SourceProcess, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
    // We are going to copy memory in our process, so we set target as ourself
    PEPROCESS TargetProcess = fnk2.PsGetCurrentProcess();

    SIZE_T Result;
    // -----DANGER-----:
    // The MmCopyVirtualMemory function is basically undocumented and it's pretty
    // dangerous to use. If the process terminate during the copy is probably going
    // to cause a BSOD. May be here some more checks are required (suspending the thread?)
    if (NT_SUCCESS(fnk2.MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result)))
        return STATUS_SUCCESS;
    else
        return STATUS_ACCESS_DENIED;
}

NTSTATUS CreateFileName(PCSTR fileBase, PCSTR fileAddress, PANSI_STRING fullPath)
{
    ANSI_STRING ansiBase, ansiAddress, ansiSeq;
    NTSTATUS status;

    // Allocate some memory for the sequence number
    PBYTE TmpString;
    TmpString = (PBYTE)fnk.ExAllocatePool(0, MAX_OUTSTRING);
    if (!TmpString) {
        return E_OUTOFMEMORY;
    }

    // Initialize ANSI_STRING structures
    fnk.RtlInitAnsiString(&ansiBase, fileBase);
    fnk.RtlInitAnsiString(&ansiAddress, fileAddress);
    fnk.RtlZeroMemory(TmpString, MAX_OUTSTRING);
    IntegerToHexString(fileSeq, TmpString);
    fnk.RtlInitAnsiString(&ansiSeq, TmpString );

    // Calculate the total length for the concatenated string
    USHORT totalLength = ansiBase.Length + ansiAddress.Length + ansiSeq.Length + 1;

    // Allocate memory for the concatenated string
    fullPath->Buffer = fnk.ExAllocatePool(0, totalLength);
    if (!fullPath->Buffer) {
        fnk.ExFreePool(TmpString);
        return E_OUTOFMEMORY;
    }
    fnk.RtlZeroMemory(fullPath->Buffer, totalLength);

    // Initialize the concatenated string
    fullPath->Length = 0;
    fullPath->MaximumLength = totalLength;

    // Append all the strings
    status = fnk2.RtlAppendStringToString(fullPath, &ansiBase);
    if (!NT_SUCCESS(status)) {
        fnk.ExFreePool(TmpString);
        fnk.ExFreePool(fullPath->Buffer);
        return status;
    }
    status = fnk2.RtlAppendStringToString(fullPath, &ansiAddress);
    if (!NT_SUCCESS(status)) {
        fnk.ExFreePool(TmpString);
        fnk.ExFreePool(fullPath->Buffer);
        return status;
    }
    status = fnk2.RtlAppendStringToString(fullPath, &ansiSeq);
    if (!NT_SUCCESS(status)) {
        fnk.ExFreePool(TmpString);
        fnk.ExFreePool(fullPath->Buffer);
        return status;
    }

    fnk.ExFreePool(TmpString);
    return STATUS_SUCCESS;
}

NTSTATUS WriteDump(PKMDDATA pk, PBYTE MemBuffer, SIZE_T BufferSize, PVOID BaseAddress)
{
    OBJECT_ATTRIBUTES _oa;
    UNICODE_STRING _su;
    ANSI_STRING _sa;
    IO_STATUS_BLOCK _io_local;
    HANDLE hFileDump;
    NTSTATUS status;

    ANSI_STRING concatenatedString;

    PBYTE BaseAddressString;
    BaseAddressString = (PBYTE)fnk.ExAllocatePool(0, MAX_OUTSTRING);
    if (!BaseAddressString) {
        return E_OUTOFMEMORY;
    }

    PointerToHexString(&BaseAddress, BaseAddressString);
    CreateFileName(pk->dataInStr, BaseAddressString, &concatenatedString);
    fnk.ExFreePool(BaseAddressString);

    // Initialize strings
    fnk.RtlInitAnsiString(&_sa, concatenatedString.Buffer);
    fnk.RtlAnsiStringToUnicodeString(&_su, &_sa, TRUE);
    fnk.RtlZeroMemory(&_oa, sizeof(OBJECT_ATTRIBUTES));
    fnk.RtlZeroMemory(&_io_local, sizeof(IO_STATUS_BLOCK));
    InitializeObjectAttributes(
        &_oa,
        &_su,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    // Open the file, but check IRQL before
    /* FIXME
    if(fnk.KeGetCurrentIrql() != PASSIVE_LEVEL) {
            // REMEMBER TO FREE UNICODE STRING AND CONCATENATED
            return STATUS_UNSUCCESSFUL;
    }
    */
    // FIXME
    status = fnk.ZwCreateFile(&hFileDump, GENERIC_WRITE, &_oa, &_io_local, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if(status) {
        fnk.RtlFreeUnicodeString(&_su);
        fnk.ExFreePool(concatenatedString.Buffer);
        return status;
    }
    fnk.ZwWriteFile(hFileDump, NULL, NULL, NULL, &_io, MemBuffer, (ULONG)BufferSize, 0, 0);
    fnk.ZwClose(hFileDump);

    // Cleanup
    fnk.ExFreePool(concatenatedString.Buffer);
    fnk.RtlFreeUnicodeString(&_su);

    return STATUS_SUCCESS;
}

NTSTATUS DumpMem(PKMDDATA pk, HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T RegionSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS Process;
    PBYTE MemBuffer;

    // Get a PEPROCESS object to be passed to MmCopyVirtualMemory
    status = HandleToPEPROCESS(ProcessHandle, &Process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Allocate memory buffer
    MemBuffer = (PBYTE)fnk.ExAllocatePool(0, RegionSize);
    if(!MemBuffer) {
        status = E_OUTOFMEMORY;
        goto cleanup_dumpmem;
    }

    // TODO: copy to memory buffer and inspect to see what contains (entropy?)
    status = ReadRegion(Process, BaseAddress, MemBuffer, RegionSize);
    if (!NT_SUCCESS(status)) {
        goto cleanup_dumpmem;
    }

    // Write memory buffer to disk
    status = WriteDump(pk, MemBuffer, RegionSize, BaseAddress);

    //  Clean up
cleanup_dumpmem:
    if (Process) {
        fnk2.ObDereferenceObject(Process);
    }
    if (MemBuffer) {
        fnk.ExFreePool(MemBuffer);
    }

    return status;
}

NTSTATUS InitVirtualMemoryRegions(HANDLE ProcessHandle)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID baseAddress = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returnLength;

    // Iterate over the address space
    while (NT_SUCCESS(status))
    {
        status = fnk2.ZwQueryVirtualMemory(ProcessHandle,
                                           baseAddress,
                                           MemoryBasicInformation,
                                           &mbi,
                                           sizeof(mbi),
                                           &returnLength);

        if (NT_SUCCESS(status))
        {
            if ((PCHAR)mbi.BaseAddress != 0 && (PCHAR)mbi.AllocationBase != 0) {
                regions[lastRegionUsed].BaseAddress = (PCHAR)mbi.BaseAddress;
                regions[lastRegionUsed].RegionSize = mbi.RegionSize;
                regions[lastRegionUsed].State = mbi.State;
                regions[lastRegionUsed].Protect = mbi.Protect;

                lastRegionUsed += 1;
                // Force to not overcome the limit
                if (lastRegionUsed > MAX_REGIONS) lastRegionUsed = MAX_REGIONS;
            }
        }
        else if (status == STATUS_INVALID_PARAMETER)
        {
            // This status code indicates that there are no more regions to enumerate
            status = STATUS_SUCCESS;
            break;
        }
        else
        {
            // Handle other types of errors here
            break;
        }
        // Move to the next region in the address space
        baseAddress = (PCHAR)mbi.BaseAddress + mbi.RegionSize;
    }
    return status;
}

VOID WriteLogResult(NTSTATUS status)
{
    PBYTE outString;
    outString = (PBYTE)fnk.ExAllocatePool(0, MAX_OUTSTRING);

    CHAR str_dump1[] = { 'D', 'u', 'm', 'p', 'e', 'd', ' ', 'S', 'e', 'q', ' ', };
    fnk.ZwWriteFile(hFile, NULL, NULL, NULL, &_io, str_dump1, 11, 0, 0);

    IntegerToHexString(fileSeq, outString);
    fnk.ZwWriteFile(hFile, NULL, NULL, NULL, &_io, outString, sizeof(SIZE_T) * 2, 0, 0);

    CHAR str_dump2[] = { ':', ' ' };
    fnk.ZwWriteFile(hFile, NULL, NULL, NULL, &_io, str_dump2, 2, 0, 0);

    IntegerToHexString(status, outString);
    fnk.ZwWriteFile(hFile, NULL, NULL, NULL, &_io, outString, sizeof(NTSTATUS) * 2, 0, 0);

    outString[0] = '\n';
    fnk.ZwWriteFile(hFile, NULL, NULL, NULL, &_io, outString, 1, 0, 0);

    fnk.ExFreePool(outString);
}

NTSTATUS QueryAllVirtualMemoryRegions(PKMDDATA pk, HANDLE ProcessHandle)
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS dumpStatus = STATUS_SUCCESS;

    PVOID baseAddress = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returnLength;

    // Iterate over the address space
    while (NT_SUCCESS(status))
    {
        status = fnk2.ZwQueryVirtualMemory(ProcessHandle,
                                           baseAddress,
                                           MemoryBasicInformation,
                                           &mbi,
                                           sizeof(mbi),
                                           &returnLength);

        if (NT_SUCCESS(status))
        {
            // Process the memory region information from mbi here

            if ((PCHAR)mbi.BaseAddress != 0 && (PCHAR)mbi.AllocationBase != 0) {
                BOOL regionFound = FALSE;

                // Browse all current entries
                for(QWORD i = 0; i <= lastRegionUsed; i++) {
                    if (regions[i].BaseAddress == (PCHAR)mbi.BaseAddress) {
                        regionFound = TRUE;

                        // Check for change in parameters
                        if (mbi.Protect != regions[i].Protect) {
                            if (mbi.Protect & PAGE_EXECUTE ||
                                    mbi.Protect & PAGE_EXECUTE_READ ||
                                    mbi.Protect & PAGE_EXECUTE_READWRITE ||
                                    mbi.Protect & PAGE_EXECUTE_WRITECOPY) {

                                // Dump memory area
                                dumpStatus = DumpMem(pk, ProcessHandle, mbi.BaseAddress, regions[i].RegionSize);
                                WriteLogResult(dumpStatus);
                                fileSeq++;
                            }

                            regions[i].Protect = mbi.Protect;
                        }
                    }
                }

                // Add new entry if needed and dump content
                if (regionFound == FALSE) {

                    regions[lastRegionUsed].BaseAddress = (PCHAR)mbi.BaseAddress;
                    regions[lastRegionUsed].RegionSize = mbi.RegionSize;
                    regions[lastRegionUsed].State = mbi.State;
                    regions[lastRegionUsed].Protect = mbi.Protect;

                    lastRegionUsed += 1;
                    // Force to not overcome the limit
                    if (lastRegionUsed > MAX_REGIONS) lastRegionUsed = MAX_REGIONS;

                    // Dump memory area
                    dumpStatus = DumpMem(pk, ProcessHandle, mbi.BaseAddress, mbi.RegionSize);
                    WriteLogResult(dumpStatus);
                    fileSeq++;
                }
            }

            // Move to the next region in the address space
            baseAddress = (PCHAR)mbi.BaseAddress + mbi.RegionSize;

        }
        else if (status == STATUS_INVALID_PARAMETER)
        {
            // This status code indicates that there are no more regions to enumerate
            status = STATUS_SUCCESS;
            break;
        }
        else
        {
            // Handle other types of errors here
            break;
        }
    }

    return status;
}

//----------------------------------------------------------------------------------------------------------
// Main
VOID c_EntryPoint(_In_ PKMDDATA pk)
{
    NTSTATUS nt;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ZwProcessHandle;
    CLIENT_ID ClientId;
    LONGLONG timeout;

    // Initialize output file sequence number
    fileSeq = 1;
    lastRegionUsed = 0;

    // Check parameters
    // Get process ID
    if(!pk->dataIn[0]) {
        pk->dataOut[0] = STATUS_INVALID_PARAMETER;
        return;
    }
    // Set the timeout, default 0x20 or passed via parameter
    if(!pk->dataIn[1]) {
        timeout = 0x20;        // Default
    } else {
        timeout = pk->dataIn[1];
    }

    InitializeKernelFunctions(pk->AddrKernelBase, &fnk);
    InitializeKernelFunctions2(pk->AddrKernelBase, &fnk2);

    fnk2.DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "-------> Starting OpenProcess :)\n");

    // open process handle
    fnk.RtlZeroMemory(&ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
    fnk.RtlZeroMemory(&ClientId, sizeof(CLIENT_ID));
    ClientId.UniqueThread = 0;
    ClientId.UniqueProcess = (HANDLE)pk->dataIn[0];
    nt = fnk2.ZwOpenProcess(&ZwProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
    if(NT_ERROR(nt)) {
        pk->dataOut[0] = nt;
        return;
    }

    // Prepare file for output
    OBJECT_ATTRIBUTES _oa;
    UNICODE_STRING _su;
    ANSI_STRING _sa;

    // Initialize strings
    fnk.RtlInitAnsiString(&_sa, pk->dataInStr);
    fnk.RtlAnsiStringToUnicodeString(&_su, &_sa, TRUE);
    fnk.RtlZeroMemory(&_oa, sizeof(OBJECT_ATTRIBUTES));
    fnk.RtlZeroMemory(&_io, sizeof(IO_STATUS_BLOCK));
    InitializeObjectAttributes(
        &_oa,
        &_su,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    // Open the file, but check IRQL before
    if(fnk.KeGetCurrentIrql() != PASSIVE_LEVEL) {
        pk->dataOut[0] = (QWORD)STATUS_UNSUCCESSFUL;
        goto cleanup_main;
    }
    nt = fnk.ZwCreateFile(&hFile, GENERIC_WRITE, &_oa, &_io, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if(nt) {
        pk->dataOut[0] = nt;
        goto cleanup_main;
    }

    // Loop and query memory regions
    LARGE_INTEGER startTime, currentTime;
    LONGLONG elapsedTime;

    // Create a baseline with all the current regions
    InitVirtualMemoryRegions(ZwProcessHandle);

    fnk2.KeQuerySystemTimePrecise(&startTime);
    while (TRUE) {
        QueryAllVirtualMemoryRegions(pk, ZwProcessHandle);

        // Check for timeout
        fnk2.KeQuerySystemTimePrecise(&currentTime);
        // Calculate elapsed time in seconds
        elapsedTime = (currentTime.QuadPart - startTime.QuadPart) / 10000000;
        // Break the loop after X seconds
        if (elapsedTime >= timeout) {
            break;
        }

        // FIXME - Evaluate if necessary to pause a bit between checks
        CommonSleep(&fnk, 5);
    }

    // Close output file
    fnk.ZwClose(hFile);
    fnk.ZwClose(ZwProcessHandle);

cleanup_main:
    fnk.RtlFreeUnicodeString(&_su);
}
