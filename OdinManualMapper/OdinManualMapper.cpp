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
	if (pNtHeaders->FileHeader.Machine != VAL_PC)
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
				printf("Successfully wrote %.8s section %d/%hu with size %zu with RVA 0x%X, VA %p\n", pSectionHeader->Name, i + 1, countSections, size, pSectionHeader->VirtualAddress, (uintptr_t)targetAddress);
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

BOOL __forceinline OdinManualMapper::RelocateImage(ShellCodeStructure* pStruct) {

	BYTE* pBase = pStruct->pRemoteTargetBase;
	PIMAGE_OPTIONAL_HEADER pOptHeader = pStruct->pOptHeader;


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
			UINT EntryCount = (pReloc->SizeOfBlock - sizeof(DWORD) * 2) / sizeof(WORD);// SizeOfCommentedoutArray
			WORD* pBaseReloc = reinterpret_cast<WORD*>((reinterpret_cast<BYTE*>(pReloc) + sizeof(IMAGE_BASE_RELOCATION))); //Add two DWORDS to access Offsets

			for (int i = 0; i < EntryCount; i++, pBaseReloc++) {

				if (ACTUAL_FLAG(*pBaseReloc)) { //high 4 bits
					UINT_PTR* toPatch = reinterpret_cast<UINT_PTR*>(pBase + pReloc->VirtualAddress + (*pBaseReloc & 0x0FFF)); //low 12 bits
					*toPatch += delta;
				}
			}
			pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
		}

	}

	return TRUE;
}

BOOL __forceinline OdinManualMapper::ResolveImports(ShellCodeStructure* pStruct) {

	BYTE* pBase = pStruct->pRemoteTargetBase;
	PIMAGE_OPTIONAL_HEADER pOptHeader = pStruct->pOptHeader;

	if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		return FALSE;
	}
	else {
		auto ImportRVA = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + ImportRVA);

		while (pImportDirectory->Name) { //Process the thunks
			const char* szMod = reinterpret_cast<const char*>(pBase + pImportDirectory->Name);

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
					ppFuncRef->u1.Function = reinterpret_cast<DWORD>(pStruct->pGetProcAddress(dll, ordchar));
				}
				else {
					PIMAGE_IMPORT_BY_NAME thunkContext = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pBase + (ppThunk->u1.AddressOfData));
					ppFuncRef->u1.Function = reinterpret_cast<UINT_PTR>(pStruct->pGetProcAddress(dll, thunkContext->Name));
				}

				ppThunk++;
				ppFuncRef++;
			}

			pImportDirectory++;
		}
	}
	return TRUE;
}

BOOL __forceinline OdinManualMapper::TLSCallback(ShellCodeStructure* pStruct) {

	BYTE* pBase = pStruct->pRemoteTargetBase;
	PIMAGE_OPTIONAL_HEADER pOptHeader = pStruct->pOptHeader;

	if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		return TRUE;
	}

	auto tlsRVA = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	PIMAGE_TLS_DIRECTORY tlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pBase + tlsRVA);
	PIMAGE_TLS_CALLBACK* ppCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsDir->AddressOfCallBacks);

	if (!ppCallback) {
		return FALSE;
	}

	while (*ppCallback) {
		(*ppCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		ppCallback++;
	}

	return TRUE;
}

BOOL __forceinline OdinManualMapper::ResolveFunctionTable(ShellCodeStructure* pStruct) {
	if (!pStruct->pRtlAddFunctionTable) {
		return FALSE;
	}

	BYTE* pBase = pStruct->pRemoteTargetBase;

	UINT_PTR ExceptionDirRVA = pStruct->pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	DWORD ExceptionDirSize = pStruct->pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

	PRUNTIME_FUNCTION pRuntimeFunc = reinterpret_cast<PRUNTIME_FUNCTION>(pBase + ExceptionDirRVA);

	if (!pRuntimeFunc) {
		return FALSE;
	}
	DWORD count = ExceptionDirSize / sizeof(PRUNTIME_FUNCTION);

	pStruct->pRtlAddFunctionTable(pRuntimeFunc, count, (DWORD64)pBase);

	return TRUE;

}

void _stdcall OdinManualMapper::Shellcode(ShellCodeStructure* pStruct) {


	if (!pStruct->pRemoteTargetBase) {
		return;
	}

	PIMAGE_NT_HEADERS pNewHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pStruct->pRemoteTargetBase + reinterpret_cast<PIMAGE_DOS_HEADER>(pStruct->pRemoteTargetBase)->e_lfanew);
	pStruct->pNtHeader = pNewHeaders;
	PIMAGE_OPTIONAL_HEADER pNewOptHeader = &(pNewHeaders->OptionalHeader);
	pStruct->pOptHeader = pNewOptHeader;

	pStruct->pDllEntry = reinterpret_cast<f_DLL_ENTRY_POINT>(pStruct->pRemoteTargetBase + pNewOptHeader->AddressOfEntryPoint);


	if (!RelocateImage(pStruct)) {
		return;
	} 

	if (!ResolveImports(pStruct)) {
		return;
	}

	if (!TLSCallback(pStruct)) {
		return;
	} 


#ifdef _WIN64
	if (!ResolveFunctionTable(pStruct)) {
		return;
	}
#endif

	if (!pStruct->pDllEntry) {
		return;
	}
	pStruct->pDllEntry(reinterpret_cast<void*>(pStruct->pRemoteTargetBase), DLL_PROCESS_ATTACH, nullptr);
	pStruct->FINISHED = true;
}


BOOL OdinManualMapper::ManualMap(HANDLE hProc, BYTE* pSrcData) {
	if (!VerifyPEFile(pSrcData))
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

		if (!pRemoteTargetBase)
		{
			printf("Failed to allocate memory in target process. Error: %d\n", GetLastError());
			CloseHandle(hProc);
			return FALSE;
		}
	}
	inj_track.pRemoteTargetBase = pRemoteTargetBase; //What address is given to us by system
	//Add PE headers to target process (REMOVE WHEN INJECTED)

	if (!WriteProcessMemory(hProc, pRemoteTargetBase, pSrcData, pOptHeader->SizeOfHeaders, nullptr)) {
		printf("Failure to write into process memory after allocation. Error: %d\n", GetLastError());
		VirtualFreeEx(hProc, pRemoteTargetBase, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return FALSE;
	}

	//Starting mapping
	if (!OdinManualMapper::MapSections(inj_track.process, inj_track.pRemoteTargetBase, inj_track.pSrcData, inj_track.pNtHeaders)) {
		printf("Error with MapSections! %d\n", GetLastError());
		return FALSE;
	}
	printf("Mapping Section success. Remote Target base: %p Creating Shellcode structure.\n", pRemoteTargetBase);

	HMODULE hK32Local = GetModuleHandleA("kernel32.dll");
	if (!hK32Local) {
		printf("Error getting kernel32\n");
		VirtualFreeEx(hProc, pRemoteTargetBase, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return false;
	}

	f_RtlAddFunctionTable pRtlAddFuncTableLocal = (f_RtlAddFunctionTable)GetProcAddress(hK32Local, "RtlAddFunctionTable");
	f_LoadLibraryA pLoadLibraryALocal = (f_LoadLibraryA)GetProcAddress(hK32Local, "LoadLibraryA");
	f_GetProcAddress pGetProcAddressLocal = (f_GetProcAddress)GetProcAddress(hK32Local, "GetProcAddress");

	ShellCodeStructure Struct{ 0 };
	Struct.pRemoteTargetBase = pRemoteTargetBase;
	Struct.pLoadLibraryA = pLoadLibraryALocal;
	Struct.pGetProcAddress = pGetProcAddressLocal;
	Struct.reason = DLL_PROCESS_ATTACH;
	Struct.reserved = nullptr;


#ifdef _WIN64
	Struct.pRtlAddFunctionTable = pRtlAddFuncTableLocal;
#endif

	printf("Shellcode structure ready. Allocating shellcode page in target process.\n");
	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pShellcode) {
		printf("Mem Alloc for Shellcode failed, reverting changes. Error: %d\n", GetLastError());
		VirtualFreeEx(hProc, pRemoteTargetBase, 0, MEM_RELEASE);
		//VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return FALSE;
	}

	void* pShellcodeStructure = VirtualAllocEx(hProc, nullptr, sizeof(Struct), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //whatever offset we get is good
	printf("Shellcode allocation ready. Allocating shellcode structure in target process.\n");
	if (!pShellcodeStructure) {
		printf("Mem Alloc for Shellcode Structure failed, reverting changes. Error: %d\n", GetLastError());
		VirtualFreeEx(hProc, pRemoteTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		//VirtualFreeEx(hProc, pShellcodeStructure, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return FALSE;
	}

	printf("Shellcode structure and function allocated. Writing to target process.\n");

	WriteProcessMemory(hProc, pShellcodeStructure, &Struct, sizeof(Struct), nullptr);
	WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr);
	printf("Creating thread in target process.\n");
	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pShellcodeStructure, 0, nullptr);

	if (!hThread) {
		printf("Thread Creation Failure, error: %d\n", GetLastError());
		VirtualFreeEx(hProc, pRemoteTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return FALSE;
	}

	CloseHandle(hThread);

	BOOL state = FALSE;
	while (!state) {
		ShellCodeStructure retStruct{ 0 };
		ReadProcessMemory(hProc, pShellcodeStructure, &retStruct, sizeof(retStruct), nullptr);
		state = retStruct.FINISHED;
		Sleep(15);
	}

	printf("Success!\n");
	//todo cleanup
	VirtualFreeEx(hProc, pRemoteTargetBase, 0, MEM_RELEASE);
	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);

	return TRUE;
}