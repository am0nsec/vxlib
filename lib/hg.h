/**
* @file         hg.h
* @date         27-10-2020
* @author       Paul Laine (@am0nsec)
* @version      1.0
* @brief        C 99 portable implementation of the hell's gate technique
* @details
* @link         https://github.com/am0nsec/DynamicWrapperEx
* @copyright    This project has been released under the GNU Public License v3 license.
*/
#ifndef __HELLS_GATE_H_GUARD_
#define __HELLS_GATE_H_GUARD_

#include <windows.h>
#include <winternl.h>

#define RETURN_ON_ERROR(hr) "if (FAILED(hr)) {return hr;}"

#define NTDLL_MODULE_PATH L"C:\\Windows\\System32\\ntdll.dll"
#define NTDLL_MODULE_NAME "ntdll.dll"

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
	_In_     ULONG              DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_    PIO_STATUS_BLOCK   IoStatusBlock,
	_In_     ULONG              ShareAccess,
	_In_     ULONG              OpenOptions
);

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
 * @brief Free an UNICODE_STRING buffer.
 * @param pString
*/
VOID HgpFreeUnicodeString(
	_Inout_ PUNICODE_STRING pString
) {
  if (pString->Buffer)
		RtlZeroMemory(pString, pString->Length);
}

/**
 * @brief
 * @param pNtCreateSection
 * @param pTNtOpenFile
 * @return
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT HgpMapViewOfModule(
	_In_ TNtCreateSection* pNtCreateSection,
	_In_ TNtOpenFile*      pNtOpenFile
) {
	// Initialise variables
	HANDLE hModuleHandle = INVALID_HANDLE_VALUE;
	IO_STATUS_BLOCK IOStatus = { 0 };
	UNICODE_STRING FileName = { 0 };

	HgpInitUnicodeString(&FileName, NTDLL_MODULE_PATH);
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, &FileName, NULL, NULL, NULL);

	// Get handle to the file
	NTSTATUS nt = (*pNtOpenFile)(&hModuleHandle, FILE_READ_ACCESS, &ObjectAttributes, &IOStatus, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
	if (!NT_SUCCESS(nt)) {
		HgpFreeUnicodeString(&FileName);
		return E_FAIL;
	}
	HgpFreeUnicodeString(&FileName);



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

	TNtCreateSection NtCreateSection = (TNtCreateSection)GetProcAddress(hNtdllModule, "NtCreateSection");
	TNtOpenFile NtOpenFile = (TNtOpenFile)GetProcAddress(hNtdllModule, "NtOpenFile");
	if (NtCreateSection == NULL || NtOpenFile == NULL)
		return E_FAIL;

	RETURN_ON_ERROR(HgpMapViewOfModule(&NtCreateSection, &NtCreateSection));
	return S_OK;
}

#endif // !__HELLS_GATE_H_GUARD_
