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

BOOL OdinManualMapper::MapSections(HANDLE hProc, BYTE* pRemoteTargetBase, BYTE* pSrcData, PIMAGE_NT_HEADERS pNtHeaders) {
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	WORD countSections = pNtHeaders->FileHeader.NumberOfSections;

	for (int i = 0; i < countSections; i++) {

		if (pSectionHeader->SizeOfRawData) {
			printf("Mapping section: %s to RVA 0x%X\n", pSectionHeader->Name, pSectionHeader->VirtualAddress);
			LPVOID targetAddress = pRemoteTargetBase + pSectionHeader->VirtualAddress;
			LPCVOID buffer = pSrcData + pSectionHeader->PointerToRawData;
			SIZE_T size = pSectionHeader->SizeOfRawData;
			if (WriteProcessMemory(
				hProc,
				targetAddress,
				buffer,
				size,
				NULL
			)) {
				printf("Successfully wrote section %d/%hu with size %zu with RVA 0x%X, VA 0x%X", i, countSections, size, pSectionHeader->VirtualAddress, (DWORD)targetAddress);
			}
			else {
				printf("Error mapping section %d/%hu. Reverting changes.", i, countSections);
				VirtualFreeEx(hProc, pRemoteTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	return true;
}

BOOL OdinManualMapper::RelocateImage(BYTE* pRemoteTargetBase, PIMAGE_OPTIONAL_HEADER pOptHeader) {
	ULONGLONG prefBase = pOptHeader->ImageBase;
	ULONGLONG delta = (ULONGLONG)((ULONGLONG)pRemoteTargetBase - prefBase);

	if (delta == 0) {
		printf("Relocation skipped, image already at preferred base.");
		return TRUE;
	}
	else {
		IMAGE_DATA_DIRECTORY relocDir = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if (relocDir.Size == 0 || relocDir.VirtualAddress == 0) {
			printf("Relocation Directory is not initialized or can't be located. Aborting.");
			return FALSE;
		}

	}
}

BOOL OdinManualMapper::ManualMap(HANDLE hProc, BYTE* pSrcData) {
	if(!VerifyPEFile(pSrcData))
	{
		printf("PE file verification failed.\n");
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pSrcData + reinterpret_cast<PIMAGE_DOS_HEADER>(pSrcData)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeaders->OptionalHeader;
		
	InjectionData inj_track{};
	inj_track.pSrcData = pSrcData;
	inj_track.process = hProc;
	//Create a new section in the target process with the size of the image

	BYTE* pRemoteTargetBase = reinterpret_cast<BYTE*>(
		VirtualAllocEx(hProc, reinterpret_cast<LPVOID>(pOptHeader->ImageBase), pOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		);

	if (!pRemoteTargetBase) 
	{
		printf("Failed to allocate memory in target process. Trying System allocation. Error: %d\n", GetLastError());

		pRemoteTargetBase = reinterpret_cast<BYTE*>(
			VirtualAllocEx(hProc, NULL, pOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
			);

		if(!pRemoteTargetBase)
		{
			printf("Failed to allocate memory in target process. Error: %d\n", GetLastError());
			return FALSE;
		}
	}
	inj_track.pRemoteTargetBase = pRemoteTargetBase; //What address is given to us by system
	//Add PE headers to target process (REMOVE WHEN INJECTED)

	if (!WriteProcessMemory(hProc, pRemoteTargetBase, pSrcData, pOptHeader->SizeOfHeaders, nullptr)) {
		VirtualFreeEx(hProc, pRemoteTargetBase, 0, MEM_RELEASE);
		return FALSE;
	}

	//Starting mapping
	if(!OdinManualMapper::MapSections(hProc,pRemoteTargetBase,pSrcData,pNtHeaders)) {
		printf("Error with MapSections! %d", GetLastError());
		return FALSE;
	}

}