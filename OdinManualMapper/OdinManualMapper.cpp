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

	for (int i = 0; i < countSections; i++, pSectionHeader++) {

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
				printf("Successfully wrote %.8s section %d/%hu with size %zu with RVA 0x%X, VA 0x%X", pSectionHeader->Name, i, countSections, size, pSectionHeader->VirtualAddress, (DWORD)targetAddress);
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

#define RELOC_FLAG32(relocData) (((relocData>>12) & 0xF)==IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(relocData) (((relocData>>12) & 0xF)==IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define ACTUAL_FLAG RELOC_FLAG64
#else
#define ACTUAL_FLAG RELOC_FLAG32
#endif

BOOL OdinManualMapper::RelocateImage(ShellCodeStructure* pStruct) {

	BYTE* pBase = pStruct->pRemoteTargetBase;
	PIMAGE_OPTIONAL_HEADER pOptHeader = &(reinterpret_cast<PIMAGE_NT_HEADERS>(pBase +
		reinterpret_cast<PIMAGE_DOS_HEADER>(pBase)->e_lfanew))->OptionalHeader;


	ULONGLONG prefBase = pOptHeader->ImageBase;
	UINT_PTR delta = ((UINT_PTR)pBase - prefBase);
	if (delta == 0) {
		return TRUE; 
	}
	else {
		IMAGE_DATA_DIRECTORY relocDir = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if (relocDir.Size == 0 || relocDir.VirtualAddress == 0) {
			return FALSE;
		}

		PIMAGE_BASE_RELOCATION pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBase + relocDir.VirtualAddress);

		while (pReloc->VirtualAddress) 
		{
			UINT EntryCount = (pReloc->SizeOfBlock - sizeof(DWORD)*2) / sizeof(WORD);// SizeOfCommentedoutArray
			WORD* pBaseReloc = reinterpret_cast<WORD*>((reinterpret_cast<BYTE*>(pReloc)+sizeof(IMAGE_BASE_RELOCATION))); //Add two DWORDS to access Offsets

			for (int i = 0; i < EntryCount; i++, pBaseReloc++) {
				
				if (ACTUAL_FLAG(*pBaseReloc)) {
					UINT_PTR* toPatch = reinterpret_cast<UINT_PTR*>(pBase + pReloc->VirtualAddress + (*pBaseReloc & 0x0FFF));
					*toPatch += delta;
				}
			}
			pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
		}

	}

	return TRUE;
}

BOOL OdinManualMapper::ResolveImports(ShellCodeStructure* pStruct) {

	BYTE* pBase = pStruct->pRemoteTargetBase;
	PIMAGE_OPTIONAL_HEADER pOptHeader = &(reinterpret_cast<PIMAGE_NT_HEADERS>(pBase +
		reinterpret_cast<PIMAGE_DOS_HEADER>(pBase)->e_lfanew))->OptionalHeader;

	if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		return FALSE;
	}
	else {
		auto ImportRVA = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + ImportRVA);

		while (pImportDirectory->Name) { //Process the thunks
			const char* szMod = reinterpret_cast<const char*>(pBase + pImportDirectory->Name);
			
			pStruct->pLoadLibraryA = LoadLibraryA;
			pStruct->pGetProcAddress = GetProcAddress;
			HINSTANCE dll = pStruct->pLoadLibraryA(szMod);

			if (!dll) {
				return FALSE;
			}

			PIMAGE_THUNK_DATA ppThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pImportDirectory->OriginalFirstThunk);
			PIMAGE_THUNK_DATA ppFuncRef = reinterpret_cast<PIMAGE_THUNK_DATA>(pBase + pImportDirectory->FirstThunk);

			if (!ppThunk) {
				ppThunk = ppFuncRef;
			}

			while (ppThunk->u1.AddressOfData) {
				if (ppThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					UINT ordinal = IMAGE_ORDINAL(ppThunk->u1.Ordinal);
					const char* ordchar = reinterpret_cast<const char*>(ordinal);
					ppThunk->u1.Function = reinterpret_cast<DWORD>(pStruct->pGetProcAddress(dll, ordchar));
				}
				else {
					PIMAGE_IMPORT_BY_NAME thunkContext = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pBase + (ppThunk->u1.AddressOfData));
					ppThunk->u1.Function = reinterpret_cast<UINT_PTR>(pStruct->pGetProcAddress(dll,thunkContext->Name));
				}

				ppThunk++;
			}


		}	
	}
	return TRUE;
}


void _stdcall OdinManualMapper::Shellcode(ShellCodeStructure* pStruct) {

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
	inj_track.pNtHeaders = pNtHeaders;
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

	if (!WriteProcessMemory(inj_track.process, inj_track.pRemoteTargetBase, inj_track.pSrcData, pOptHeader->SizeOfHeaders, nullptr)) {
		VirtualFreeEx(hProc, pRemoteTargetBase, 0, MEM_RELEASE);
		return FALSE;
	}

	//Starting mapping
	if(!OdinManualMapper::MapSections(inj_track.process, inj_track.pRemoteTargetBase, inj_track.pSrcData, inj_track.pNtHeaders)) {
		printf("Error with MapSections! %d", GetLastError());
		return FALSE;
	}

}