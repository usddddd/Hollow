package core

func ReadRegistryKey(hive, key string) string {

	open_key := "// Add legitimate-looking operations between suspicious calls\nDWORD dummy = GetTickCount();\nSleep(rand() % 1000 + 500);\n  // Random delay (500-1500ms)\n// Read some registry keys (legitimate activity)\nHKEY hKey;\nRegOpenKeyExA(HKEY_LOCAL_MACHINE,\"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\",0, KEY_READ, &hKey);\nRegCloseKey(hKey);\n"

	return open_key
}
