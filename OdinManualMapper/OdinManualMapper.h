#pragma once

#include <stdio.h> 
#include <windows.h>

namespace OdinManualMapper
{
	BOOL ManualMap(HANDLE hProcess, BYTE* pSrcData);
	BOOL VerifyPEFile(BYTE* pSrcData);
}