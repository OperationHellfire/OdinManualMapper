#pragma once

#include <stdio.h> 
#include <windows.h>

namespace OdinManualMapper
{
	struct InjectionData {
		HANDLE process;
		BYTE* pRemoteTargetBase;
		BYTE* pSrcData;
		SIZE_T imageSize;
		
	};


	BOOL ManualMap(HANDLE hProcess, BYTE* pSrcData);
	BOOL VerifyPEFile(BYTE* pSrcData);
	BOOL MapSections(HANDLE hProc, BYTE* pRemoteTargetBase, BYTE* pSrcData, PIMAGE_NT_HEADERS pNtHeaders);
	BOOL RelocateImage(BYTE* pRemoteTargetBase, PIMAGE_OPTIONAL_HEADER pOptHeader);
}