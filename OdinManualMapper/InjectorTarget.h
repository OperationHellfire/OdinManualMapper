#pragma once
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
namespace InjectorTarget {
	DWORD GetProcessByName(const wchar_t* processName);	
}
