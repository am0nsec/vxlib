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

INT wmain() {
	HRESULT hr = HgInitialise();
	if (SUCCEEDED(hr))
		return 0x00;
	else
		return 0x01;
}