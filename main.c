/**
* @file         main.c
* @date         27-10-2020
* @author       Paul Laine (@am0nsec)
* @version      1.0
* @brief        Main file for test purposes.
* @details
* @link         https://github.com/am0nsec/vxlib
* @copyright    This project has been released under the GNU Public License v3 license.
*/
#include <windows.h>

#include "lib/hg.h"



typedef NTSTATUS(STDMETHODCALLTYPE* TNtAllocateVirtualMemory) (
	HANDLE    ProcessHandle,
	PVOID*    BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

// NtCreateThreadEx
typedef NTSTATUS(STDMETHODCALLTYPE* TNtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN  ACCESS_MASK DesiredAccess,
	IN  PVOID ObjectAttributes,
	IN  HANDLE ProcessHandle,
	IN  PVOID lpStartAddress,
	IN  PVOID lpParameter,
	IN  ULONG Flags,
	IN  SIZE_T StackZeroBits,
	IN  SIZE_T SizeOfStackCommit,
	IN  SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
);

typedef NTSTATUS(STDMETHODCALLTYPE* TNtWaitForSingleObject)(
	IN HANDLE               ObjectHandle,
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       TimeOut OPTIONAL
);

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}

INT wmain() {

	HG_DATA HgData = { 0 };
	HRESULT hr = HgInitialise(&HgData);

	// Resolve all functions
	TNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
	DWORD dwHash = 0x80a6b89b;
	HgGetFunction(&HgData, &dwHash, (LPVOID)&NtAllocateVirtualMemory);

	TNtCreateThreadEx NtCreateThreadEx = NULL;
	dwHash = 0x88c5015f;
	HgGetFunction(&HgData, &dwHash, (LPVOID)&NtCreateThreadEx);

	TNtWaitForSingleObject NtWaitForSingleObject = NULL;
	dwHash = 0x4e551bcb;
	HgGetFunction(&HgData, &dwHash, (LPVOID)&NtWaitForSingleObject);


	HgUninitialise(&HgData, TRUE);

	// Execute shellcode
	PVOID lpBaseAddress = NULL;
	SIZE_T sDataSize = 0x1000;
	NTSTATUS nt = NtAllocateVirtualMemory((HANDLE)-1, &lpBaseAddress, 0, &sDataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	char shellcode[] = "\x90\x90\x90\x90\xcc\xcc\xcc\xcc\xc3";
	VxMoveMemory(lpBaseAddress, shellcode, sizeof(shellcode));

	// Create thread
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	nt = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	// Wait for 1 seconds
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = 0x10000;
	nt = NtWaitForSingleObject(hHostThread, FALSE, &Timeout);

	return 1;
}