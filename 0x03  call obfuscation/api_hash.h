#pragma once
#include <iostream>
#include <Windows.h>
#include <winternl.h>

// 编译时随机种子生成器 
constexpr int RandomCompileTimeSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

// 全局编译时随机密钥
constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;


// 字符串哈希 (ASCII)
constexpr DWORD HashStringDjb2A(const char* String) {
    ULONG Hash = (ULONG)g_KEY; // 使用随机种子初始化
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << 5) + Hash) + c;
    }
    return Hash;
}

// 字符串哈希 (WideChar)
constexpr DWORD HashStringDjb2W(const wchar_t* String) {
    ULONG Hash = (ULONG)g_KEY; // 使用随机种子初始化
    INT c = 0;
    while ((c = *String++)) {
        if (c >= 'A' && c <= 'Z') c += 32;
        Hash = ((Hash << 5) + Hash) + c;
    }
    return Hash;
}

HMODULE MyGetModuleHandleH(DWORD dwDllHash) {
#ifdef _WIN64 
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    PPEB pPeb = (PEB*)(__readfsdword(0x30));
#endif

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    while (pDte) {
        if (pDte->FullDllName.Length != NULL) {
            // 使用 HashStringDjb2W 计算当前 DLL 名的哈希并对比
            if (HashStringDjb2W(pDte->FullDllName.Buffer) == dwDllHash) {
#ifdef STRUCTS
                return (HMODULE)(pDte->InMemoryOrderLinks.Flink);
#else
                return (HMODULE)(pDte->Reserved2[0]);
#endif
            }
        }
        else {
            break;
        }
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    return NULL;
}

PVOID MyGetProcAddressH(HMODULE handle, DWORD dwApiHash) {
    if (handle == NULL) return NULL;

    PBYTE pBase = (PBYTE)handle;

    PIMAGE_DOS_HEADER pdosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pdosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pdosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_OPTIONAL_HEADER peOptionHeader = pImageNtHeaders->OptionalHeader;

    if (peOptionHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportVirtualAddress = (PIMAGE_EXPORT_DIRECTORY)(pBase + peOptionHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pExportVirtualAddress->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pExportVirtualAddress->AddressOfFunctions);
    PWORD ordinArray = (PWORD)(pBase + pExportVirtualAddress->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportVirtualAddress->NumberOfNames; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

        // 使用 HashStringDjb2A 计算当前函数名的哈希并对比
        if (HashStringDjb2A(pFunctionName) == dwApiHash) {
            return (PVOID)(pBase + FunctionAddressArray[ordinArray[i]]);
        }
    }
    return NULL;
}

//  辅助宏 
#define CTIME_HASHA( STR ) HashStringDjb2A( STR )
#define CTIME_HASHW( STR ) HashStringDjb2W( STR )