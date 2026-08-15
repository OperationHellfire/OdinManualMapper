#pragma once

#include <stdio.h> 
#include <windows.h>


typedef HMODULE (WINAPI* f_LoadLibraryA) (const char* lpLibFileName);
typedef FARPROC (WINAPI* f_GetProcAddress) (HMODULE hModule, const char* lpProcName);
typedef BOOL (WINAPI* f_DLL_ENTRY_POINT) (void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
typedef BOOLEAN (WINAPI* f_RtlAddFunctionTable) (PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif


namespace OdinManualMapper
{
	struct InjectionData {
		HANDLE process;
		BYTE* pRemoteTargetBase;
		BYTE* pSrcData;
		PIMAGE_NT_HEADERS pNtHeaders;
		SIZE_T imageSize;
	};

	struct ShellCodeStructure {
		f_LoadLibraryA pLoadLibraryA; // Pointer to LoadLibraryA function
		f_GetProcAddress pGetProcAddress; // pointer to GetProcAddress function
#ifdef _WIN64
		f_RtlAddFunctionTable pRtlAddFunctionTable; // pointer to RtlAddFunctionTable function (WIN64 ONLY, NEED TO INSPECT FURTHER)
#endif
		BYTE* pRemoteTargetBase; // Pointer to the base address of the injected module in the target process
		DWORD pOptHeader_EntryPoint; // Might as well calculate this once and pass it to the shellcode, saves time
		LPVOID reserved; // dll reserved parameter for DllMain
		DWORD reason; // ^ same as above, but for reason parameter
	};


	BOOL ManualMap(HANDLE hProcess, BYTE* pSrcData);
	BOOL VerifyPEFile(BYTE* pSrcData);
	BOOL MapSections(HANDLE hProc, BYTE* pRemoteTargetBase, BYTE* pSrcData, PIMAGE_NT_HEADERS pNtHeaders);
	BOOL RelocateImage(ShellCodeStructure* pStruct);
	BOOL ResolveImports(ShellCodeStructure* pStruct);

	void _stdcall Shellcode(ShellCodeStructure* pStruct);
}