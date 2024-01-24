#ifndef STRUCTS_HPP
#define STRUCTS_HPP

#include <windows.h>

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

#endif //STRUCTS_HPP
