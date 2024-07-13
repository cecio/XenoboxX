// wx64_strings.c :
// Compatible with Windows x64.
//
// Display strings in process memory
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_strings.c
// ml64.exe wx64_common_a.asm /Fewx64_strings.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_strings.obj wx64_common.obj
// shellcode64.exe -o wx64_strings.exe "DISPLAY STRINGS IN MEMORY                            \n===============================================================\nREQUIRED OPTIONS:                                              \n  -0   : Process PID to open. Example '-0 0x0fe0'.        \nOPTIONAL OPTIONS:                                              \n  -1   : Process monitoring timeout Default: 0x01. Example:  '-1 0x100'. \n  -2   : ASCII (0x0) or WIDE (0x1) string. Default: 0x0\n  -3   : String minimum length. Default: 0xA\n  -4   : Search only Writable memory pages (0x0) or all (0x01). Default: 0x0\n===== RESULT OF STRINGS OPERATION ======================%s\nNTSTATUS  : 0x%08X                                             \n===============================================================\n"
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
#define H_strlen                                0x672F5BA8
#define H_wcslen                                0x692E4BAA
#define H_toupper                               0x64FF6CAA
#define H_towupper                              0x64EB7B2E

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
    // String manipulation API
    size_t (*strlen)(
        const char                    *String1
    );
    size_t (*wcslen)(
        const wchar_t                 *String1
    );
    int (*toupper)(
        int                           c
    );
    int (*towupper)(
        wint_t                        c
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
        { &fnk2->strlen,                            H_strlen},
        { &fnk2->wcslen,                            H_wcslen},
        { &fnk2->toupper,                           H_toupper},
        { &fnk2->towupper,                          H_towupper},
    };
    for(QWORD j = 0; j < (sizeof(FUNC2) / sizeof(QWORD[2])); j++) {
        *(PQWORD)FUNC2[j][0] = PEGetProcAddressH(qwNtosBase, (DWORD)FUNC2[j][1]);
    }
}

KERNEL_FUNCTIONS fnk;
KERNEL_FUNCTIONS2 fnk2;

//----------------------------------------------------------------------------------------------------------

VOID AsciiToWideString(const char* asciiStr, wchar_t* wideStr, size_t maxLen) {
    while (*asciiStr && --maxLen) {
        *wideStr++ = (wchar_t)*asciiStr++;
    }
    *wideStr = L'\0';
}

PVOID KernelGrep(PVOID buffer, SIZE_T bufferSize, const PVOID searchString, BOOLEAN Wide, BOOLEAN CaseSensitive, SIZE_T startOffset, BOOLEAN convToWide) {
    if (!buffer || !searchString) {
        return NULL;
    }

    // Start the search from startOffset
    SIZE_T i = startOffset;

    if (Wide) {

        wchar_t* wBuffer = (wchar_t*)buffer;
        SIZE_T wSearchLength;
        const wchar_t* wSearchString;

        if (convToWide) {
            wchar_t wideSearchString[256];
            // Convert ASCII searchString to wide string
            AsciiToWideString((const char*)searchString, wideSearchString, sizeof(wideSearchString) / sizeof(wchar_t));

            wSearchString = (const wchar_t*)wideSearchString;
        } else {
            wSearchString = (const wchar_t*)searchString;
        }
        wSearchLength = (SIZE_T)fnk2.wcslen(wSearchString);

        for (; i < bufferSize / sizeof(wchar_t); ++i) {
            if (i + wSearchLength > bufferSize / sizeof(wchar_t)) {
                break; // Prevent buffer overflow
            }

            // Scan for substring match
            SIZE_T j;
            for (j = 0; j < wSearchLength; ++j) {
                wchar_t c1 = wBuffer[i + j];
                wchar_t c2 = wSearchString[j];
                if (CaseSensitive ? (c1 != c2) : (fnk2.towupper(c1) != fnk2.towupper(c2))) {
                    break;
                }
            }

            if (j == wSearchLength) { // Full match found
                // Find the end of the string
                SIZE_T len = wSearchLength;
                while (i + len < bufferSize / sizeof(wchar_t) && wBuffer[i + len] != L'\0') {
                    ++len;
                }
                return &wBuffer[i];
            }
        }
    } else {
        char* cBuffer = (char*)buffer;
        const char* cSearchString = (const char*)searchString;
        SIZE_T cSearchLength = (SIZE_T)fnk2.strlen(cSearchString);

        for (; i < bufferSize; ++i) {
            if (i + cSearchLength > bufferSize) {
                break; // Prevent buffer overflow
            }

            // Scan for substring match
            SIZE_T j;
            for (j = 0; j < cSearchLength; ++j) {
                char c1 = cBuffer[i + j];
                char c2 = cSearchString[j];
                if (CaseSensitive ? (c1 != c2) : (fnk2.toupper(c1) != fnk2.toupper(c2))) {
                    break;
                }
            }

            if (j == cSearchLength) { // Full match found
                // Find the end of the string
                SIZE_T len = cSearchLength;
                while (i + len < bufferSize && cBuffer[i + len] != '\0') {
                    ++len;
                }
                return &cBuffer[i];
            }
        }
    }

    return NULL;
}

//----------------------------------------------------------------------------------------------------------

BOOLEAN IsPrintableChar(char c) {
    return c >= 32 && c <= 126;
}

BOOLEAN IsPrintableWChar(wchar_t wc) {
    // Define the range of printable wide characters as needed
    return (wc >= L' ' && wc <= L'~') || (wc >= L'0' && wc <= L'9') || (wc >= L'A' && wc <= L'Z') || (wc >= L'a' && wc <= L'z');
}

PVOID FindPrintableString(PVOID buffer, SIZE_T bufferSize, SIZE_T minLen, BOOLEAN isWideChar, SIZE_T offset) {
    if (!buffer) {
        return NULL;
    }

    SIZE_T currentLength = 0;
    PVOID currentStringStart = NULL;

    if (isWideChar) {
        wchar_t* wBuffer = (wchar_t*)buffer;
        for (size_t i = offset; i < bufferSize / sizeof(wchar_t); ++i) {
            if (IsPrintableWChar(wBuffer[i])) {
                if (currentLength == 0) {
                    currentStringStart = &wBuffer[i];
                }
                currentLength++;
            } else if (currentLength >= minLen) {
                offset = i + 1;
                return currentStringStart;
            } else {
                currentLength = 0;
            }
        }
    } else {
        char* cBuffer = (char*)buffer;
        for (size_t i = offset; i < bufferSize; ++i) {
            if (IsPrintableChar(cBuffer[i])) {
                if (currentLength == 0) {
                    currentStringStart = &cBuffer[i];
                }
                currentLength++;
            } else if (currentLength >= minLen) {
                offset = i + 1;
                return currentStringStart;
            } else {
                currentLength = 0;
            }
        }
    }

    if (currentLength >= minLen) {
        return currentStringStart;
    }

    return NULL;
}

//----------------------------------------------------------------------------------------------------------

VOID print_string(_In_ PKMDDATA pk, const void *src, int isWide) {
    QWORD qwAddrOut;
    UINT offset = 0;

    // Prepare the pointer for the output
    qwAddrOut = pk->DMAAddrVirtual + pk->dataOutExtraOffset + pk->dataOutExtraLength;

    if (isWide) {
        const wchar_t *wsrc = (const wchar_t *)src;
        DWORD chunk = 0;
        UINT count = 0;

        while (*wsrc) {
            chunk |= (*wsrc) << (count * 8);
            count+=2;
            wsrc++;

            // Every 4 bytes or end of the string, copy to output buffer
            if (count == 4 || *wsrc == L'\0') {
                *(PDWORD)(qwAddrOut + offset) = chunk;
                offset += 4;

                chunk = 0;
                count = 0;
            }
        }

        // Handle the last, potentially incomplete, chunk
        if (count > 0) {
            *(PDWORD)(qwAddrOut + offset) = chunk;
            offset += 4;
        } else {
            // Add an additional end-of-string
            *(PDWORD)(qwAddrOut + offset) = 0;
            offset += 4;
        }
    } else {
        const char *csrc = (const char *)src;
        DWORD chunk = 0;
        UINT count = 0;

        while (*csrc) {
            chunk |= ((DWORD)(*csrc) & 0xFF) << (count * 8);
            count++;
            csrc++;

            if (count == 4 || *csrc == '\0') {
                *(PDWORD)(qwAddrOut + offset) = chunk;
                offset += 4;
                chunk = 0;
                count = 0;
            }
        }

        if (count > 0) {
            *(PDWORD)(qwAddrOut + offset) = chunk;
            offset += 4;
        } else {
            // Add an additional end-of-string
            *(PDWORD)(qwAddrOut + offset) = 0;
            offset += 4;
        }
    }
    pk->dataOutExtraLength += offset;
}

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

NTSTATUS SearchMem(PKMDDATA pk, HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T RegionSize, BOOLEAN Wide, SIZE_T minLen)
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
        goto cleanup_searchmem;
    }

    // Copy to memory buffer
    status = ReadRegion(Process, BaseAddress, MemBuffer, RegionSize);
    if (!NT_SUCCESS(status)) {
        goto cleanup_searchmem;
    }

    // Search the string in buffer
    SIZE_T offset = 0;
    PVOID result;
    QWORD qwAddrOutBase;
    qwAddrOutBase = pk->DMAAddrVirtual + pk->dataOutExtraOffset;
    while ((result = FindPrintableString(MemBuffer, RegionSize, minLen, Wide, offset)) != NULL) {

        if (KernelGrep((PVOID) qwAddrOutBase, pk->dataOutExtraLength, result, Wide, 1, 0, 0) == NULL) {
            print_string(pk, result, Wide);
        }

        // Update offset for next search
        if (Wide) {
            offset = ((const wchar_t*)result - (const wchar_t*)MemBuffer) + 1;
        } else {
            offset = ((const char*)result - (const char*)MemBuffer) + 1;
        }

        if (offset >= RegionSize) {
            break;
        }
    }

    //  Clean up
cleanup_searchmem:
    if (Process) {
        fnk2.ObDereferenceObject(Process);
    }
    if (MemBuffer) {
        fnk.ExFreePool(MemBuffer);
    }

    return status;
}

NTSTATUS QueryAllVirtualMemoryRegions(PKMDDATA pk, HANDLE ProcessHandle, BOOLEAN Wide, BOOLEAN allPages, SIZE_T minLen)
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
            // Process the memory region information from mbi here

            // Search the memory region for the strings
            if (mbi.Type != MEM_IMAGE) {
                if ( allPages == TRUE || (mbi.Protect & PAGE_READWRITE ||
                                          mbi.Protect & PAGE_WRITECOPY ||
                                          mbi.Protect & PAGE_EXECUTE_READWRITE ||
                                          mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                    SearchMem(pk, ProcessHandle, mbi.BaseAddress, mbi.RegionSize, Wide, minLen);
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
    BOOLEAN isWide = FALSE;
    BOOLEAN allPages = FALSE;
    SIZE_T minLen = 10;

    // Initialize output file sequence number
    fileSeq = 1;
    lastRegionUsed = 0;

    // Check parameters
    // Process ID
    if(!pk->dataIn[0]) {
        pk->dataOut[0] = STATUS_INVALID_PARAMETER;
        return;
    }
    // Set the timeout, default 0x20
    if(!pk->dataIn[1]) {
        timeout = 0x01;        // Default
    } else {
        timeout = pk->dataIn[1];
    }
    // Set the Wide flag
    if (pk->dataIn[2] == 0) {
        isWide = FALSE;
    } else {
        isWide = TRUE;
    }
    // Set Min Length of the string
    if (pk->dataIn[3] == 0) {
        minLen = 10;
    } else {
        minLen = pk->dataIn[3];
    }
    // Set "all pages" flag
    if (pk->dataIn[4] == 0) {
        allPages = FALSE;
    } else {
        allPages = TRUE;
    }

    InitializeKernelFunctions(pk->AddrKernelBase, &fnk);
    InitializeKernelFunctions2(pk->AddrKernelBase, &fnk2);

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

    // Check IRQL
    if(fnk.KeGetCurrentIrql() != PASSIVE_LEVEL) {
        pk->dataOut[0] = (QWORD)STATUS_UNSUCCESSFUL;
        goto cleanup_main;
    }

    // Loop and query memory regions
    LARGE_INTEGER startTime, currentTime;
    LONGLONG elapsedTime;

    fnk2.KeQuerySystemTimePrecise(&startTime);
    while (TRUE) {
        // print_Iteration(pk);
        QueryAllVirtualMemoryRegions(pk, ZwProcessHandle, isWide, allPages, minLen);

        // Check for timeout
        fnk2.KeQuerySystemTimePrecise(&currentTime);
        // Calculate elapsed time in seconds
        elapsedTime = (currentTime.QuadPart - startTime.QuadPart) / 10000000;
        // Break the loop after X seconds
        if (elapsedTime >= timeout) {
            break;
        }

        // FIXME - Evaluate if necessary to pause a bit between checks
        //CommonSleep(&fnk, 5);
    }

cleanup_main:
    // Close process
    fnk.ZwClose(ZwProcessHandle);
}
