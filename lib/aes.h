/**
* @file         aes.h
* @date         14-11-2020
* @author       Paul Laine (@am0nsec)
* @version      1.0
* @brief        C 99 portable implementation Windows CNG AES Encryption.
* @details
* @link         https://github.com/am0nsec/vxlib
* @copyright    This project has been released under the GNU Public License v3 license.
*/
#ifndef __CNG_AES_H_GUARD_
#define __CNG_AES_H_GUARD_
#include <Windows.h>
#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")

/*-------------------------------------------------------------------------------------------------
  Macros.
-------------------------------------------------------------------------------------------------*/
#pragma region Macros
#define STATUS_SUCCESS 0x00000000

#define RETURN_ON_ERROR(hr) \
	if (FAILED(hr)) {return hr;}

#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif

#define RETURN_ON_NT_ERROR(nt) \
	if (NT_ERROR(nt)) {return nt;}

#pragma endregion

typedef struct _CNG_DATA {
	HANDLE hBCryptAlgorithmProvider;
	HANDLE hKey;

	PBYTE  pbIv;
	PBYTE  pbIvBack;
	DWORD  dwIvLength;

	PBYTE  pbKey;
	DWORD  dwKeyLength;

	PBYTE  pbBlob;
	DWORD  dwBlob;
} CNG_DATA, *PCNG_DATA;

/*-------------------------------------------------------------------------------------------------
  Functions.
-------------------------------------------------------------------------------------------------*/
#pragma region Functions
/**
 * @brief Generate random data via the CNG RNG Algorithm.
 * @param pdwLength Pointer to the length of the random data to generate.
 * @param ppData Pointer to memory.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT CngpGenerateRandom(
	_In_  PDWORD pdwLength,
	_Out_ PBYTE* ppData
) {
	if (pdwLength == NULL || ppData == NULL)
		return E_INVALIDARG;

	// Open handle to the RNG Algorithm Provider
	HANDLE hAlgorithm = INVALID_HANDLE_VALUE;
	RETURN_ON_NT_ERROR(BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0));

	// Generate random data
	*ppData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *pdwLength);
	NTSTATUS nt = BCryptGenRandom(hAlgorithm, *ppData, *pdwLength, BCRYPT_RNG_USE_ENTROPY_IN_BUFFER);
	if (NT_ERROR(nt)) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return E_FAIL;
	}

	// Close handle
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	return S_OK;
}

/**
 * @brief Generate a symmetric key object that can be used for AES encryption/decryption.
 * @param ppCngData Pointer to a pointer of a CNG_DATA structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT CngpGenerateSymmetricKey(
	_In_ PCNG_DATA* ppCngData
) {
	if (ppCngData == NULL || *ppCngData == NULL)
		return E_INVALIDARG;

	// Get size of key object
	DWORD dwKey = 0;
	ULONG ulKey = 0;
	RETURN_ON_NT_ERROR(BCryptGetProperty((*ppCngData)->hBCryptAlgorithmProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwKey, sizeof(DWORD), &ulKey, 0));
	if (ulKey == 0 || dwKey == 0)
		return E_FAIL;

	// Generate random Key
	PBYTE pbKey = NULL;
	ulKey = 0x400;
	RETURN_ON_ERROR(CngpGenerateRandom((PDWORD)&ulKey, &pbKey));
	(*ppCngData)->pbKey = pbKey;
	(*ppCngData)->dwKeyLength = (DWORD)ulKey;

	// Generate object
	NTSTATUS nt = BCryptGenerateSymmetricKey((*ppCngData)->hBCryptAlgorithmProvider, &(*ppCngData)->hKey, pbKey, dwKey, (*ppCngData)->pbKey, (*ppCngData)->dwKeyLength, 0);
	if (NT_ERROR(nt) || (*ppCngData)->hKey == INVALID_HANDLE_VALUE) {
		HeapFree(GetProcessHeap(), 0, pbKey);
		return E_FAIL;
	}

	// Get size of key blob
	RETURN_ON_NT_ERROR(BCryptExportKey((*ppCngData)->hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &(*ppCngData)->dwBlob, 0));

	// Allocate heap memory
	(*ppCngData)->pbBlob = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (*ppCngData)->dwBlob);
	if ((*ppCngData)->pbBlob == NULL)
		return E_OUTOFMEMORY;

	// Get key blob 
	RETURN_ON_NT_ERROR(BCryptExportKey((*ppCngData)->hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, (*ppCngData)->pbBlob, (*ppCngData)->dwBlob, &(*ppCngData)->dwBlob, 0));
	return S_OK;
}

/**
 * @brief Get size of block and move IV.
 * @param ppCngData Pointer to a pointer of a CNG_DATA structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT CngpInitialiseIv(
	_In_ PCNG_DATA* ppCngData
) {
	if (ppCngData == NULL || *ppCngData == NULL)
		return E_INVALIDARG;

	// Get length of block
	DWORD dwBlock = 0;
	ULONG ulBlock = 0;
	RETURN_ON_NT_ERROR(BCryptGetProperty((*ppCngData)->hBCryptAlgorithmProvider, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlock, sizeof(DWORD), &ulBlock, 0));
	if (ulBlock == 0 || dwBlock == 0)
		return E_FAIL;

	// Generate random IV for block length
	PBYTE pbIv = NULL;
	RETURN_ON_ERROR(CngpGenerateRandom(&dwBlock, &pbIv));
	(*ppCngData)->dwIvLength = dwBlock;
	(*ppCngData)->pbIv = pbIv;

	// Keep a backup of the IV because this will be overwritten during encryption/decryption
	(*ppCngData)->pbIvBack = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBlock);
	RtlCopyMemory((*ppCngData)->pbIvBack, (*ppCngData)->pbIv, dwBlock);
	return S_OK;
}

/**
 * @brief Import key from blob and reset IV post encryption/decryption.
 * @param ppCngData Pointer to a pointer of a CNG_DATA structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT CngpImportKeyAndReInitialiseIv(
	_In_ PCNG_DATA* ppCngData
) {
	if (ppCngData == NULL || *ppCngData == NULL)
		return E_INVALIDARG;

	// Destroy key
	RETURN_ON_NT_ERROR(BCryptDestroyKey((*ppCngData)->hKey));

	// zero'ed the key object
	RtlZeroMemory((*ppCngData)->pbKey, (*ppCngData)->dwKeyLength);

	// Get new handle to key object
	(*ppCngData)->hKey = INVALID_HANDLE_VALUE;
	RETURN_ON_NT_ERROR(BCryptImportKey(
		(*ppCngData)->hBCryptAlgorithmProvider,
		NULL,
		BCRYPT_OPAQUE_KEY_BLOB,
		&(*ppCngData)->hKey,
		(*ppCngData)->pbKey,
		(*ppCngData)->dwKeyLength,
		(*ppCngData)->pbBlob,
		(*ppCngData)->dwBlob,
		0
	));

	// Re-initialise IV
	RtlCopyMemory((*ppCngData)->pbIv, (*ppCngData)->pbIvBack, (*ppCngData)->dwIvLength);
	return S_OK;
}

/**
 * @brief Initialise CNG AES encryption algorithm provider.
 * @param pCngData Pointer of a CNG_DATA structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT CngInitialise(
	_In_ PCNG_DATA pCngData
) {
	if (pCngData == NULL)
		return E_FAIL;

	// Open handle to the AES Algorithm Provider
	RETURN_ON_NT_ERROR(BCryptOpenAlgorithmProvider(&pCngData->hBCryptAlgorithmProvider, BCRYPT_AES_ALGORITHM, NULL, 0));

	// Generate symmetric key 
	pCngData->hKey = INVALID_HANDLE_VALUE;
	RETURN_ON_ERROR(CngpGenerateSymmetricKey(&pCngData));

	// Initialise IV
	RETURN_ON_ERROR(CngpInitialiseIv(&pCngData));
	return S_OK;
}

/**
 * @brief Uninitialise CNG AES encryption algorithm provider.
 * @param pCngData Pointer of a CNG_DATA structure.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT CngUninitialise(
	_In_ PCNG_DATA pCngData
) {
	if (pCngData == NULL)
		return E_INVALIDARG;

	if (pCngData->hKey)
		BCryptDestroyKey(pCngData->hKey);

	if (pCngData->hBCryptAlgorithmProvider)
		BCryptCloseAlgorithmProvider(pCngData->hBCryptAlgorithmProvider, 0);

	if (pCngData->pbIv)
		HeapFree(GetProcessHeap(), 0, pCngData->pbIv);

	if (pCngData->pbIvBack)
		HeapFree(GetProcessHeap(), 0, pCngData->pbIvBack);

	if (pCngData->pbKey)
		HeapFree(GetProcessHeap(), 0, pCngData->pbKey);

	if (pCngData->pbBlob)
		HeapFree(GetProcessHeap(), 0, pCngData->pbBlob);

	RtlZeroMemory(pCngData, sizeof(CNG_DATA));
	return S_OK;
}

/**
 * @brief AES Encrypt a given string.
 * @param pCngData Pointer of a CNG_DATA structure
 * @param pbBuffer Pointer to a string to encrypt.
 * @param pdwBufferLength Pointer to the size of the string to encrypt.
 * @param pbEncBuffer Pointer to the encrypted string. Returned by the function.
 * @param pdwEncBufferLength Pointer to the size of the encrypted string. Returned by the function.
 * @return Whether the function successfully executed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT CngEncryptString(
	_In_  PCNG_DATA pCngData,
	_In_  PBYTE     pbBuffer,
	_In_  PDWORD    pdwBufferLength,
	_Out_ PBYTE*    ppbEncBuffer,
	_Out_ PDWORD    pdwEncBufferLength
) {
	if (pCngData == NULL || pbBuffer == NULL || pdwBufferLength == NULL || *pdwBufferLength == 0)
		return E_INVALIDARG;

	// Get the size of the output buffer
	ULONG ulCipherLength = 0;
	NTSTATUS nt = STATUS_SUCCESS;
	nt = BCryptEncrypt(pCngData->hKey, pbBuffer, *pdwBufferLength, NULL, pCngData->pbIv, pCngData->dwIvLength, NULL, 0, &ulCipherLength, BCRYPT_BLOCK_PADDING);
	if (NT_ERROR(nt) || ulCipherLength == 0)
		return E_FAIL;

	// Allocate heap memory
	*ppbEncBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulCipherLength);
	if (*ppbEncBuffer == NULL)
		return E_OUTOFMEMORY;
	*pdwEncBufferLength = ulCipherLength;

	// Encrypt buffer
	nt = BCryptEncrypt(pCngData->hKey, pbBuffer, *pdwBufferLength, NULL, pCngData->pbIv, pCngData->dwIvLength, *ppbEncBuffer, *pdwEncBufferLength, &ulCipherLength, BCRYPT_BLOCK_PADDING);
	if (NT_ERROR(nt)) {
		HeapFree(GetProcessHeap(), 0, *ppbEncBuffer);
		return E_FAIL;
	}

	RETURN_ON_ERROR(CngpImportKeyAndReInitialiseIv(&pCngData));
	return S_OK;
}

_Success_(return == S_OK) _Must_inspect_result_
HRESULT CngDecryptString(
	_In_  PCNG_DATA pCngData,
	_In_  PBYTE     pbEncBuffer,
	_In_  PDWORD    pdwEncBufferLength,
	_Out_ PBYTE*    ppbBuffer,
	_Out_ PDWORD    pdwBufferLength
) {
	if (pCngData == NULL || pbEncBuffer == NULL || pdwEncBufferLength == NULL || *pdwEncBufferLength == 0)
		return E_INVALIDARG;

	// Get size of the decrypted string
	ULONG ulPlaintextLength = 0;
	NTSTATUS nt = STATUS_SUCCESS;
	nt = BCryptDecrypt(pCngData->hKey, pbEncBuffer, *pdwEncBufferLength, NULL, pCngData->pbIv, pCngData->dwIvLength, NULL, 0, &ulPlaintextLength, BCRYPT_BLOCK_PADDING);
	if (NT_ERROR(nt) || ulPlaintextLength == 0)
		return E_FAIL;

	// Allocate heap memory
	*ppbBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulPlaintextLength);
	if (*ppbBuffer == NULL)
		return E_OUTOFMEMORY;
	*pdwBufferLength = ulPlaintextLength;

	// Decrypt buffer
	nt = BCryptDecrypt(pCngData->hKey, pbEncBuffer, *pdwEncBufferLength, NULL, pCngData->pbIv, pCngData->dwIvLength, *ppbBuffer, *pdwBufferLength, &ulPlaintextLength, BCRYPT_BLOCK_PADDING);
	if (NT_ERROR(nt)) {
		HeapFree(GetProcessHeap(), 0, *ppbBuffer);
		return E_FAIL;
	}

	RETURN_ON_ERROR(CngpImportKeyAndReInitialiseIv(&pCngData));
	return S_OK;
}

#pragma endregion
#endif // !__CNG_AES_H_GUARD_