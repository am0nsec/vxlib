/**
* @file         hg.h
* @date         14-11-2020
* @author       Paul Laine (@am0nsec)
* @version      1.0
* @brief        C 99 portable implementation of the hell's gate technique.
* @details
* @link         https://github.com/am0nsec/vxlib
* @copyright    This project has been released under the GNU Public License v3 license.
*/
#ifndef __HELLS_GATE_H_GUARD_
#define __HELLS_GATE_H_GUARD_

#include <windows.h>
#include <winternl.h>

/*-------------------------------------------------------------------------------------------------
  Macros.
-------------------------------------------------------------------------------------------------*/
#pragma region Macros
#define STATUS_SUCCESS 0x00000000

#define NTDLL_MODULE_PATH L"\\??\\C:\\Windows\\System32\\ntdll.dll"
#define NTDLL_MODULE_NAME "ntdll"

// For making the code less bloated 
#define RETURN_ON_ERROR(hr) \
	if (FAILED(hr)) {return hr;}

// Get the address of a function at runtime
#define LOAD_AND_CHECK(h, lp, name) \
	lp = (LPVOID)GetProcAddress(h, name); \
	if (lp == NULL){ return E_FAIL; }
#pragma endregion

/*-------------------------------------------------------------------------------------------------
  Type definition and structures.
-------------------------------------------------------------------------------------------------*/
#pragma region Typedef
typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         NumberOfLinks;
	BOOLEAN       DeletePending;
	BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

/**
 * @brief Data required by HG to works. 
*/
typedef struct _HG_DATA {
	// Section used for NTDLL
	HANDLE hHgSection;
	LPVOID lpHgSection;
	
	// EAT information
	DWORD  dwNumberOfNames;
	PDWORD pdwAddressOfFunctions;
	PDWORD pdwAddressOfNames;
	PWORD  pwAddressOfNameOrdinales;

	// Section used for executable function
	HANDLE hExecSection;
	LPVOID lpExecSection;
	DWORD  dwExecSection;
	WORD   wFunctionCopied;
} HG_DATA, *PHG_DATA;

/**
 * @brief Type definition of the NtCreateSection native function.
*/
typedef NTSTATUS(STDMETHODCALLTYPE* TNtCreateSection)(
	_Out_    PHANDLE            SectionHandle,
	_In_     ULONG              DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              PageAttributes,
	_In_     ULONG              SectionAttributes,
	_In_opt_ HANDLE             FileHandle
);

/**
 * @brief Type definition of the NtOpenFile native function.
*/
typedef NTSTATUS(STDMETHODCALLTYPE* TNtOpenFile)(
	_Out_    PHANDLE            FileHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
	_In_     ULONG              ShareAccess,
	_In_     ULONG              OpenOptions
);

/**
 * @brief Type definition of the NtQueryInformationFile native function.
*/
typedef NTSTATUS(STDMETHODCALLTYPE* TNtQueryInformationFile)(
	_In_  HANDLE                 FileHandle,
	_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
	_Out_ PVOID                  FileInformation,
	_In_  ULONG                  Length,
	_In_  FILE_INFORMATION_CLASS FileInformationClass
);

/**
 * @brief Type definition of the NtMapViewOfSection native function.
*/
typedef NTSTATUS(STDMETHODCALLTYPE* TNtMapViewOfSection)(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID*          BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        SECTION_INHERIT InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
);

typedef NTSTATUS(STDMETHODCALLTYPE* TNtMakeTemporaryObject) (
	_In_ HANDLE ObjectHandle
);

typedef NTSTATUS(STDMETHODCALLTYPE* TNtExtendSection) (
	_In_ HANDLE         SectionHandle,
	_In_ PLARGE_INTEGER NewSectionSize
);

typedef NTSTATUS(STDMETHODCALLTYPE* TNtUnmapViewOfSection) (
	_In_ HANDLE SectionHandle,
	_In_ PVOID  BaseAddress
);

#pragma endregion

/*-------------------------------------------------------------------------------------------------
  Global variables.
-------------------------------------------------------------------------------------------------*/
#pragma region GlobalVariables
static TNtCreateSection        g_NtCreateSection = NULL;
static TNtOpenFile             g_NtOpenFile = NULL;
static TNtQueryInformationFile g_NtQueryInformationFile = NULL;
static TNtMapViewOfSection     g_NtMapViewOfSection = NULL;
static TNtMakeTemporaryObject  g_NtMakeTemporaryObject = NULL;
static TNtExtendSection        g_NtExtendSection = NULL;
static TNtUnmapViewOfSection   g_NtUnmapViewOfSection = NULL;
#pragma endregion

/*-------------------------------------------------------------------------------------------------
  Functions.
-------------------------------------------------------------------------------------------------*/
#pragma region Functions
/**
 * @brief Initialise a UNICODE_STRING structure.
 * @param pDestination Pointer to an UNICODE_STRING structure
 * @param pSource Pointer to a unicode string.
*/
VOID HgpInitUnicodeString(
	_In_ PUNICODE_STRING pDestination,
	_In_ PCWSTR          pSource
) {
	if (pSource) {
		pDestination->Length = (USHORT)(wcslen(pSource) * sizeof(WCHAR));
		pDestination->MaximumLength = pDestination->Length + sizeof(UNICODE_NULL);
	}
	else {
		pDestination->Length = 0;
		pDestination->MaximumLength = 0;
	}
	pDestination->Buffer = (PWSTR)pSource;
}

/**
 * @brief Get the size of a file object by handle.
 * @param phFile Pointer to an handle to a file object.
 * @param pFileSize Pointer to a LARGE_INTEGER structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgpGetFileSize(
	_In_  PHANDLE        phFile,
	_Out_ PLARGE_INTEGER pFileSize
) {
	if (phFile == NULL || *phFile == INVALID_HANDLE_VALUE)
		return E_FAIL;
	
	// Structures initialisation
	FILE_STANDARD_INFORMATION FileInfo = { 0 };
	IO_STATUS_BLOCK IOStatus = { 0 };

	// Get data
	NTSTATUS nt = g_NtQueryInformationFile(*phFile, &IOStatus, (PFILE_STANDARD_INFORMATION)&FileInfo, sizeof(FILE_STANDARD_INFORMATION), 0x5);
	if (!NT_SUCCESS(nt))
		return E_FAIL;
	
	// Return value by reference
	*pFileSize = FileInfo.EndOfFile;
	return S_OK;
}

/**
 * @brief Map a fresh copy of the NTDLL module in memory.
 * @param pHgData Pointer to an HgData structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgpMapViewOfModule(
	_In_  PHG_DATA pHgData
) {
	// Initialise variables
	HANDLE hModuleHandle = INVALID_HANDLE_VALUE;
	IO_STATUS_BLOCK IOStatus = { 0 };
	UNICODE_STRING FileName = { 0 };

	HgpInitUnicodeString(&FileName, NTDLL_MODULE_PATH);
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// Get handle to the file
	NTSTATUS nt = STATUS_SUCCESS;
	nt = (g_NtOpenFile)(&hModuleHandle,	FILE_READ_DATA,	&ObjectAttributes,&IOStatus, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
	if (!NT_SUCCESS(nt))
		return E_FAIL;

	// Get file size
	LARGE_INTEGER FileSize = { 0 };
	RETURN_ON_ERROR(HgpGetFileSize(&hModuleHandle, &FileSize));

	// Create 2 un-named section executive object
	HANDLE hSectionHandle = INVALID_HANDLE_VALUE;
	nt = g_NtCreateSection(&hSectionHandle, SECTION_ALL_ACCESS, NULL, &FileSize, PAGE_READONLY, SEC_IMAGE, hModuleHandle);
	if (!NT_SUCCESS(nt) || hSectionHandle == INVALID_HANDLE_VALUE)
		return E_FAIL;
	CloseHandle(hModuleHandle);

	HANDLE hExecSection = INVALID_HANDLE_VALUE;
	LARGE_INTEGER InitialSize = { 0 };
	InitialSize.QuadPart = 32;
	nt = g_NtCreateSection(&hExecSection, SECTION_ALL_ACCESS, NULL, &FileSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(nt) || hSectionHandle == INVALID_HANDLE_VALUE)
		return E_FAIL;

	// Remove permanent flag from objects
	nt = g_NtMakeTemporaryObject(hSectionHandle);
	if (!NT_SUCCESS(nt)) {
		CloseHandle(hSectionHandle);
		return E_FAIL;
	}

	nt = g_NtMakeTemporaryObject(hExecSection);
	if (!NT_SUCCESS(nt)) {
		CloseHandle(hExecSection);
		return E_FAIL;
	}

	// Map section executive objects to process
	PVOID pSectionAddress = NULL;
	SIZE_T ulViewSize = 0;
	nt = g_NtMapViewOfSection(hSectionHandle, (HANDLE)-1, &pSectionAddress, 0, 0, NULL, &ulViewSize, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(nt))
		return E_FAIL;

	PVOID pExecSectionAddress = NULL;
	ulViewSize = 32;
	nt = g_NtMapViewOfSection(hExecSection, (HANDLE)-1, &pExecSectionAddress, 0, 0, NULL, &ulViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

	// Save the data and exit;
	pHgData->hHgSection = hSectionHandle;
	pHgData->lpHgSection = pSectionAddress;
	pHgData->hExecSection = hExecSection;
	pHgData->lpExecSection = pExecSectionAddress;
	pHgData->dwExecSection = (DWORD)ulViewSize;
	return S_OK;
}

/**
 * @brief Get the address of the functions and function name list from the section.
 * @param pHgData Pointer to an HgData structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgpGetExportAddressTable(
	_In_ PHG_DATA pHgData
) {
	if (pHgData == NULL)
		return E_INVALIDARG;

	// Check DOS Header
	PIMAGE_DOS_HEADER pImageDosHeader = pHgData->lpHgSection;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return E_FAIL;

	// Check NT Header
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pImageDosHeader + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return E_FAIL;

	// Get the address of the EAT
	DWORD64 dwExportDirectoryRva = pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pImageDosHeader + dwExportDirectoryRva);

	// Get address of name, functions and ordinals	
	pHgData->dwNumberOfNames = pImageExportDirectory->NumberOfNames;
	pHgData->pdwAddressOfFunctions = (PDWORD)((PBYTE)pImageDosHeader + pImageExportDirectory->AddressOfFunctions);
	pHgData->pdwAddressOfNames = (PDWORD)((PBYTE)pImageDosHeader + pImageExportDirectory->AddressOfNames);
	pHgData->pwAddressOfNameOrdinales = (PWORD)((PBYTE)pImageDosHeader + pImageExportDirectory->AddressOfNameOrdinals);
	return S_OK;
}

/**
 * @brief Get the DJB2 hash of a function name.
 * @param pbFunctionName The name of the function.
 * @param pdwHash Pointer to the hash value.
*/
VOID HgpGetHash(
	_In_  PBYTE  pbFunctionName,
	_Out_ PDWORD pdwHash
) {
	BYTE c = 0;
	*pdwHash = 0x77347734;
	while (c = *pbFunctionName++)
		*pdwHash = ((*pdwHash << 0x5) + *pdwHash) + c;
}

/**
 * @brief Clone the fast system call stub of a function
 * @param pHgData Pointer to a HgData structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgpCloneNativeFunction(
	_In_ PHG_DATA pHgData,
	_In_ LPVOID   lpFunctionAddress
) {
	// Resize the section to store a new function
	if (pHgData->dwExecSection <= (DWORD)(pHgData->wFunctionCopied * 32)) {
		LARGE_INTEGER NewSize = { 0 };
		NewSize.QuadPart = pHgData->dwExecSection + 0x1000;
		NTSTATUS nt = g_NtExtendSection(pHgData->hExecSection, &NewSize);
		if (NT_ERROR(nt))
			return E_FAIL;
	}

	// Copy the fast call stub
	PBYTE dst = (PBYTE)pHgData->lpExecSection + (pHgData->wFunctionCopied++ * 32);
	for (WORD cx = 0; cx < 32; cx++)
		*dst++ = *((PBYTE)lpFunctionAddress)++;
	return S_OK;
}

/**
 * @brief Initialise the Hell's Gate project by mapping a fresh copy of NTDLL module into the process.
 * @param pHgData Pointer to a HgData structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgInitialise(
	_In_ PHG_DATA pHgData
) {
	// Resolve native APIs
	HMODULE hNtdllModule = GetModuleHandleA(NTDLL_MODULE_NAME);
	if (hNtdllModule == NULL)
		return E_FAIL;

	// Resolve native APIs
	LOAD_AND_CHECK(hNtdllModule, g_NtCreateSection, "NtCreateSection");
	LOAD_AND_CHECK(hNtdllModule, g_NtOpenFile, "NtOpenFile");
	LOAD_AND_CHECK(hNtdllModule, g_NtQueryInformationFile, "NtQueryInformationFile");
	LOAD_AND_CHECK(hNtdllModule, g_NtMapViewOfSection, "NtMapViewOfSection");
	LOAD_AND_CHECK(hNtdllModule, g_NtMakeTemporaryObject, "NtMakeTemporaryObject");
	LOAD_AND_CHECK(hNtdllModule, g_NtExtendSection, "NtExtendSection");
	LOAD_AND_CHECK(hNtdllModule, g_NtUnmapViewOfSection, "NtUnmapViewOfSection");

	// Create the section executive object and map the module in memory
	RETURN_ON_ERROR(HgpMapViewOfModule(pHgData));

	// Get the Import Address Table
	RETURN_ON_ERROR(HgpGetExportAddressTable(pHgData));
	return S_OK;
}

/**
 * @brief Uninitialise the Hell's Gate project by unmaping all the sections and closing all the handles.
 * @param pHgData Pointer to a HgData structure.
 * @param bHgSection Whether the Hell's Gate Section has to be unmaped too.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgUninitialise(
	_In_ PHG_DATA pHgData,
	_In_ BOOLEAN  bHgSection
) {
	HRESULT nt = S_OK;

	if (pHgData->hExecSection) {
		nt = g_NtUnmapViewOfSection((HANDLE)-1, pHgData->lpExecSection);
		CloseHandle(pHgData->hExecSection);
	}
	if (bHgSection && pHgData->hHgSection) {
		nt = g_NtUnmapViewOfSection((HANDLE)-1, pHgData->lpHgSection);
		CloseHandle(pHgData->hHgSection);
	}

	RtlZeroMemory(pHgData, sizeof(HG_DATA));
	return S_OK;
}

/**
 * @brief Find and clone a function based on function name hash.
 * @param pHgData Pointer to a HgData structure 
 * @param pdwHash Pointer to the 32-bit DJB2 hash of the function name.
 * @param ppFunction Pointer to a function pointer.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgGetFunction(
	_In_  PHG_DATA pHgData,
	_In_  PDWORD   pdwHash,
	_Out_ LPVOID*  ppFunction
) {
	if (pdwHash == NULL)
		return E_FAIL;

	// Find the function
	for (DWORD cx = 0; cx < pHgData->dwNumberOfNames; cx++) {
		LPCSTR cszFunctionName = ((PBYTE)pHgData->lpHgSection + pHgData->pdwAddressOfNames[cx]);

		// Get hash of the function;
		DWORD dwHash = 0;
		HgpGetHash((PBYTE)cszFunctionName, &dwHash);
		if (dwHash != *pdwHash)
			continue;

		// Get address of the function
		*ppFunction = (PBYTE)pHgData->lpHgSection + pHgData->pdwAddressOfFunctions[pHgData->pwAddressOfNameOrdinales[cx]];
		if (*ppFunction == NULL)
			return E_FAIL;

		return HgpCloneNativeFunction(pHgData, *ppFunction);
	}
	return E_FAIL;
}

#pragma endregion
#endif // !__HELLS_GATE_H_GUARD_
