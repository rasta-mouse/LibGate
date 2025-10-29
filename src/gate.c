#include <windows.h>
#include "gate.h"

#define SYS_STUB_SIZE 32
#define UP -SYS_STUB_SIZE
#define DOWN SYS_STUB_SIZE

BOOL GetSyscall(PVOID ntdll, PVOID func, SYSCALL_GATE * gate)
{
    PIMAGE_DOS_HEADER pDosHdr          = NULL;
    PIMAGE_NT_HEADERS pNtHdrs          = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;

    DWORD dwSyscallNr = 0;
    PVOID pIndirect   = NULL;

    PDWORD pdwAddrOfFunctions  = NULL;
    PWORD pwAddrOfNameOrdinals = NULL;
    
    WORD wIdxStub  = 0;
    WORD wIdxfName = 0;
    BOOL bHooked   = FALSE;

    pDosHdr    = (PIMAGE_DOS_HEADER)ntdll;
    pNtHdrs    = (PIMAGE_NT_HEADERS)((PBYTE)ntdll + pDosHdr->e_lfanew);
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdll + pNtHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);

    pdwAddrOfFunctions   = (PDWORD)((PBYTE)ntdll + pExportDir->AddressOfFunctions);
    pwAddrOfNameOrdinals = (PWORD)((PBYTE)ntdll + pExportDir->AddressOfNameOrdinals);

    for (wIdxStub = 0; wIdxStub < SYS_STUB_SIZE; wIdxStub++)
    {
        if (*((PBYTE)func + wIdxStub) == 0xe9) {
            bHooked = TRUE;
            break;
        }

        if (*((PBYTE)func + wIdxStub) == 0xc3)
            return FALSE;

        if (*((PBYTE)func + wIdxStub) == 0x4c &&
            *((PBYTE)func + wIdxStub + 1) == 0x8b &&
            *((PBYTE)func + wIdxStub + 2) == 0xd1 &&
            *((PBYTE)func + wIdxStub + 3) == 0xb8 &&
            *((PBYTE)func + wIdxStub + 6) == 0x00 &&
            *((PBYTE)func + wIdxStub + 7) == 0x00) {

                BYTE low  = *((PBYTE)func + 4 + wIdxStub);
                BYTE high = *((PBYTE)func + 5 + wIdxStub);

                dwSyscallNr = (high << 8) | low;

                break;
        }
    }

    if (bHooked)
    {
        for (wIdxfName = 1; wIdxfName <= pExportDir->NumberOfFunctions; wIdxfName++) {
            if ((PBYTE)func + wIdxfName * DOWN < ((PBYTE)ntdll + pdwAddrOfFunctions[pwAddrOfNameOrdinals[pExportDir->NumberOfFunctions - 1]])) {
                if (*((PBYTE)func + wIdxfName * DOWN) == 0x4c &&
                    *((PBYTE)func + 1 + wIdxfName * DOWN) == 0x8b &&
                    *((PBYTE)func + 2 + wIdxfName * DOWN) == 0xd1 &&
                    *((PBYTE)func + 3 + wIdxfName * DOWN) == 0xb8 &&
                    *((PBYTE)func + 6 + wIdxfName * DOWN) == 0x00 &&
                    *((PBYTE)func + 7 + wIdxfName * DOWN) == 0x00) {

                        BYTE high = *((PBYTE)func + 5 + wIdxfName * DOWN);
                        BYTE low  = *((PBYTE)func + 4 + wIdxfName * DOWN);
                        
                        dwSyscallNr = (high << 8) | (low - wIdxfName);
                        func        = (PVOID)((PBYTE)func + wIdxfName * DOWN);

                        break;
                }
            }

            if ((PBYTE)func + wIdxfName * UP > ((PBYTE)ntdll + pdwAddrOfFunctions[pwAddrOfNameOrdinals[0]])) {

                if (*((PBYTE)func + wIdxfName * UP) == 0x4c &&
                    *((PBYTE)func + 1 + wIdxfName * UP) == 0x8b &&
                    *((PBYTE)func + 2 + wIdxfName * UP) == 0xd1 &&
                    *((PBYTE)func + 3 + wIdxfName * UP) == 0xb8 &&
                    *((PBYTE)func + 6 + wIdxfName * UP) == 0x00 &&
                    *((PBYTE)func + 7 + wIdxfName * UP) == 0x00) {

                        BYTE high = *((PBYTE)func + 5 + wIdxfName * UP);
                        BYTE low  = *((PBYTE)func + 4 + wIdxfName * UP);
                        
                        dwSyscallNr = (high << 8) | (low + wIdxfName);
                        func        = (PVOID)((PBYTE)func + wIdxfName * UP);

                        break;
                }
            }
        }
    }

    if (func && dwSyscallNr)
    {
        for (wIdxStub = 0; wIdxStub < SYS_STUB_SIZE; wIdxStub++)
        {
            if (*((PBYTE)func + wIdxStub) == 0x0f &&
                *((PBYTE)func + wIdxStub + 1) == 0x05 &&
                *((PBYTE)func + wIdxStub + 2) == 0xc3) {
                    pIndirect = (LPVOID)((PBYTE)func + wIdxStub);
                    break;
            }
        }
    }

    /* set values */
    gate->ssn     = dwSyscallNr;
    gate->jmpAddr = pIndirect;

    return TRUE;
}

void __attribute__((naked)) PrepareSyscall(DWORD ssn, PVOID addr)
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "xor r11, r11;"
        "xor r10, r10;"
        "mov r11, rcx;"
        "mov r10, rdx;"
        "ret;"
        ".att_syntax prefix"
    );
}

void __attribute__((naked)) DoSyscall()
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "push r10;"
        "xor rax, rax;"
        "mov r10, rcx;"
        "mov eax, r11d;"
        "ret;"
        ".att_syntax prefix"
    );
}