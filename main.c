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
#include <stdio.h>

#include "lib/aes.h"

INT wmain() {
	CNG_DATA CngData = { 0 };
	HRESULT hr = CngInitialise(&CngData);
	
	// Prologue
	LPSTR szBuffer1 = "cum lux abest, tenebrae vincunt";
	LPWSTR szBuffer2 = L"instrumentum regni";
	printf("String 1 to encrypt: %s\n", szBuffer1);
	wprintf(L"String 2 to encrypt: %s\n\n", szBuffer2);
	DWORD dwBuffer1 = (DWORD)strlen(szBuffer1);
	DWORD dwBuffer2 = (DWORD)wcslen(szBuffer2) * sizeof(WCHAR);

	// Encrypt stuff
	PBYTE pbEncBuffer1 = NULL;
	PBYTE pbEncBuffer2 = NULL;
	DWORD dwEncBuffer1 = 0;
	DWORD dwEncBuffer2 = 0;
	hr = CngEncryptString(&CngData, szBuffer1, &dwBuffer1, &pbEncBuffer1, &dwEncBuffer1);
	hr = CngEncryptString(&CngData, szBuffer2, &dwBuffer2, &pbEncBuffer2, &dwEncBuffer2);


	// Decrypt stuff
	LPSTR szDecBuffer1 = NULL;
	LPWSTR szDecBuffer2 = NULL;
	DWORD dwDecBuffer1 = 0;
	DWORD dwDecBuffer2 = 0;
	hr = CngDecryptString(&CngData, pbEncBuffer1, &dwEncBuffer1, &szDecBuffer1, &dwDecBuffer1);
	hr = CngDecryptString(&CngData, pbEncBuffer2, &dwEncBuffer2, &szDecBuffer2, &dwDecBuffer2);

	// Print output 
	printf("String 1 decrypted:  %s\n", szDecBuffer1);
	wprintf(L"String 2 decrypted:  %s\n\n", szDecBuffer2);

	// Release everything
	hr = CngUninitialise(&CngData);
	return 1;
}