#include <windows.h>

template <int N, int K>
struct ObfuscatedString
{
    char data[N];

    constexpr ObfuscatedString(const char (&str)[N], const char (&key)[K]) : data{}
    {
        for (int i = 0; i < N; i++)
        {
            data[i] = str[i] ^ key[i % K];
        }
    }

    void decrypt(char *output, char *key) const
    {
        for (int i = 0; i < N; i++)
        {
            output[i] = data[i] ^ key[i % K];
        }
    }
};

#define OBFSTR(str, key) []() -> const char * { \
    constexpr auto obf = ObfuscatedString<sizeof(str), sizeof(key)>(str, key); \
    static char decrypted[sizeof(str)]; \
    obf.decrypt(decrypted, key); \
    return decrypted; }()

int test_obfstr()
{
    const char *k32 = OBFSTR("kernel32.dll", "testkey");
    const char *va = OBFSTR("VirtualAllocEx", "testkey");

    HMODULE hMod = GetModuleHandleA(k32);
    FARPROC pFunc = GetProcAddress(hMod, va);

    if (!hMod || !pFunc)
    {
        return 1;
    }
    return 0;
}