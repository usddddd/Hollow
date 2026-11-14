// hash_calculator.cpp — run this to compute hashes for any API name
#include <stdio.h>

unsigned int djb2(const char *str)
{
    unsigned int hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

int main(int argc, char *argv[])
{
    const char *apis[] = {
        "VirtualAlloc", "VirtualProtect", "VirtualFree",
        "CreateThread", "RtlMoveMemory", "WaitForSingleObject",
        "GetModuleHandleA", "GetProcAddress", "LoadLibraryA",
        "OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "NtAllocateVirtualMemory",
        "kernel32.dll", "ntdll.dll", "user32.dll", "bcrypt.dll"};

    for (int i = 0; i < sizeof(apis) / sizeof(apis[0]); i++)
    {
        printf("#define HASH_%-30s 0x%08X\n", apis[i], djb2(apis[i]));
    }
    return 0;
}
