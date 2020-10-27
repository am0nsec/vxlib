/**
* @file         hg.h
* @date         27-10-2020
* @author       Paul Laine (@am0nsec)
* @version      1.0
* @brief        C 99 portable implementation of the hell's gate technique
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

// For making the code 
#define RETURN_ON_ERROR(hr) if (FAILED(hr)) {return hr;}
#define LOAD_AND_CHECK(h, lp, name) lp = GetProcAddress(h, name); if (lp == NULL){ return E_FAIL; }
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

static HANDLE                  g_hProcessHeap = INVALID_HANDLE_VALUE;
static HANDLE                  g_hSectionHandle = INVALID_HANDLE_VALUE;
static LPVOID                  g_lpSectionAddress = NULL;

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
		pDestination->Length = wcslen(pSource) * sizeof(WCHAR);
		pDestination->MaximumLength = pDestination->Length + sizeof(UNICODE_NULL);
	}
	else {
		pDestination->Length = 0;
		pDestination->MaximumLength = 0;
	}
	pDestination->Buffer = pSource;
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
 * @param phSectionHandle Pointer to an handle to a section executive object.
 * @param pSectionAddress Pointer to the base address of the section executive object.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgpMapViewOfModule(
	_Out_ PHANDLE phSectionHandle,
	_Out_ LPVOID* ppSectionAddress
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

	// Create un-named section executive object
	HANDLE hSectionHandle = INVALID_HANDLE_VALUE;
	nt = g_NtCreateSection(&hSectionHandle, SECTION_ALL_ACCESS, NULL, &FileSize, PAGE_READONLY, SEC_IMAGE, hModuleHandle);
	if (!NT_SUCCESS(nt) || hSectionHandle == INVALID_HANDLE_VALUE)
		return E_FAIL;
	CloseHandle(hModuleHandle);

	// Remove permanent flag from object
	nt = g_NtMakeTemporaryObject(hSectionHandle);
	if (!NT_SUCCESS(nt)) {
		CloseHandle(hSectionHandle);
		return E_FAIL;
	}

	// Map section executive object to process
	PVOID pSectionAddress = NULL;
	SIZE_T ulViewSize = 0;
	nt = g_NtMapViewOfSection(hSectionHandle, (HANDLE)-1, &pSectionAddress, NULL, NULL,	NULL, &ulViewSize, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(nt))
		return E_FAIL;

	*phSectionHandle = hSectionHandle;
	*ppSectionAddress = pSectionAddress;
	return S_OK;
}

/**
 * @brief Initialise the Hell's Gate project by mapping a fresh copy of NTDLL module into the process.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgInitialise() {
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

	// Get handle to process heap
	g_hProcessHeap = GetProcessHeap();

	// Create the section executive object and map the module in memory
	HRESULT hr = HgpMapViewOfModule(&g_hSectionHandle, &g_lpSectionAddress);
	if (FAILED(hr) || g_hSectionHandle == INVALID_HANDLE_VALUE || g_lpSectionAddress == NULL)
		return E_FAIL;

	// Get the Import Address Table
	// TODO

	return S_OK;
}

#pragma endregion
#endif // !__HELLS_GATE_H_GUARD_
