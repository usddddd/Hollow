#include <windows.h>

template <int N, int K>
struct ObfuscatedString
{
    char data[N];

    constexpr ObfuscatedString(const char(&str)[N], const char(&key)[K]) : data{}
    {
        for (int i = 0; i < N; i++)
        {
            data[i] = str[i] ^ key[i % K];
        }
    }

    void decrypt(char* output, char* key) const
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

// Function which imports common gui winapis but doesn't use them.
void InitWindowSubsystem() {
    if (GetCurrentProcessId() == 0) {
        BOOL b = FALSE;
        int n = 0;
        LRESULT lr = 0;
        HRESULT hr = S_OK;
        DWORD dw = 0;
        HWND hWnd = NULL;
        HDC hDc = NULL;
        HICON hIco = NULL;

        b = GetClientRect(NULL, NULL);
        n = DrawTextW(NULL, NULL, NULL, NULL, NULL);
        b = SetWindowTextW(NULL, NULL);
        b = InvalidateRect(NULL, NULL, NULL);
        lr = SendMessageW(NULL, NULL, NULL, NULL);
        hIco = LoadIconW(NULL, NULL);
        n = GetSystemMetrics(NULL);
        b = EnumWindows(NULL, NULL);
        hWnd = GetForegroundWindow();
        hDc = GetDC(NULL);
        n = ReleaseDC(NULL, hDc);
        hr = CoInitializeEx(NULL, NULL);
        CoUninitialize();
        dw = ExpandEnvironmentStringsW(NULL, NULL, NULL);
        b = GetUserNameW(NULL, NULL);
    }
}

int test_obfstr()
{
    const char* k32 = OBFSTR("kernel32.dll", "testkey");
    const char* va = OBFSTR("VirtualAllocEx", "testkey");

    HMODULE hMod = GetModuleHandleA(k32);
    FARPROC pFunc = GetProcAddress(hMod, va);

    if (!hMod || !pFunc)
    {
        return 1;
    }
    return 0;
}