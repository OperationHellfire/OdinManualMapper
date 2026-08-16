#include <iostream>
#include "InjectorTarget.h"
#include <fstream>
#include "OdinManualMapper.h"

int main(int argc, char* argv[]) {
	if (argc != 3) {
		std::cout << "Arguments needed: targetprocess.exe dllfile.dll" << argc <<std::endl;
		return 1;
	}

	size_t newsize = strlen(argv[1]) + 1;

	wchar_t* wcstring = new wchar_t[newsize];

	size_t convertedChars = 0;

	mbstowcs_s(&convertedChars, wcstring, newsize, argv[1], _TRUNCATE);

	DWORD processPID = InjectorTarget::GetProcessByName(wcstring);

	delete[] wcstring;
	if (processPID == 0) {
		std::cout << "Target process not found, quitting." << std::endl;
		return 1;
	}
	else {
		std::cout << "Target process found. Getting DLL." << std::endl;
	}

	std::ifstream dllFile(argv[2], std::ios::binary | std::ios::ate);

	if (!dllFile.is_open()) {
		std::cout << "Error opening DLL file!" << std::endl;
		dllFile.close();
		return 1;
	}
	else {
		std::cout << "DLL file opened." << std::endl;
	}

	std::streampos fileSize = dllFile.tellg();


	BYTE* pSrcData = new BYTE[static_cast<UINT_PTR>(fileSize)];

	if (!pSrcData) {
		std::cout << "Initial pre-inject Memory allocation failed!" << std::endl;
		delete[] pSrcData;
		return 1;
	}

	dllFile.seekg(0, std::ios::beg);
	dllFile.read(reinterpret_cast<char*>(pSrcData), fileSize);
	dllFile.close();


	std::cout << "Getting handle" << std::endl;



	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processPID);

	if (!hProc) {
		std::cout << "Error opening process with PID " << processPID << std::endl;
		delete[] pSrcData;
		return 1;
	}

	if (OdinManualMapper::ManualMap(hProc, pSrcData)) {
		std::cout << "Successfully injected!" << std::endl;
	}
	else {
		std::cout << "Error: " << GetLastError() << std::endl;
	}

	return 0;


} 