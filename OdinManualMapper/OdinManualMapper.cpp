// OdinManualMapper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "OdinManualMapper.h"


BOOL OdinManualMapper::VerifyPEFile(BYTE* pSrcData)
{
	PIMAGE_DOS_HEADER pointerPE = reinterpret_cast<PIMAGE_DOS_HEADER>(pSrcData);
	if (pointerPE->e_magic != IMAGE_DOS_SIGNATURE) // IMAGE_DOS_SIGNATURE = 0x5A4D
	{
		printf("Invalid DOS signature.\n");
		return FALSE;
	}

	//Architecture check

	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pSrcData + pointerPE->e_lfanew);

#ifdef _WIN64
#define VAL_PC IMAGE_FILE_MACHINE_AMD64
#else
#define VAL_PC IMAGE_FILE_MACHINE_I386
#endif
	if(pNtHeaders->FileHeader.Machine != VAL_PC)
	{
		printf("Architecture check failed, please make sure dll matches pc architecture.\n");
		return FALSE;
	}

	printf("PE file verified successfully.\n");
	return TRUE;
	
}

BOOL OdinManualMapper::ManualMap(HANDLE hProc, BYTE* pSrcData) {

	if(!VerifyPEFile(pSrcData))
	{
		printf("PE file verification failed.\n");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pSrcData + reinterpret_cast<PIMAGE_DOS_HEADER>(pSrcData)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeaders->OptionalHeader;
	PIMAGE_FILE_HEADER pFileHeader = &pNtHeaders->FileHeader;
}