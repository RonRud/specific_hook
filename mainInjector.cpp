#include <Windows.h>
#include <iostream>
//#include <stdio.h>
// #include <tlhelp32.h>
#include <string>

bool InjectDLL(DWORD ProcessID)
{

	char thisFilePath[100] = { 0 };

	GetModuleFileName(NULL, thisFilePath, 100);
	std::string DllPath = std::string(thisFilePath);
	const size_t last_slash_idx = DllPath.rfind('\\'); //Get the last occurareance of \\ (before the exe name)
	if (std::string::npos != last_slash_idx) {
		DllPath = DllPath.substr(0, last_slash_idx + 1) + "DLL.dll"; // Than add the dll file name to it
	};



	//Get the current memory location of LoadLibraryA function in the current loaded instance of kernel32.dll
	LPVOID llAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (!llAddress) { // if GetProcAddress fails than it will return null and go in this error
		std::cout << "Error: cant get procAddress, error code: " << std::hex << GetLastError() << std::endl;
		return false;
	}
	//Get access to the process that the program desires to hook
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
	if (!hProcess) {
		std::cout << "Error: cant open Process!, error code: " << std::hex << GetLastError() << std::endl;
		return false;
	}
	//Save the full path of the injected dll in the inspected process (needs to be in it's address space in order to be called by a thread in the other process)
	LPVOID lpDllAddress = VirtualAllocEx(hProcess, NULL, strlen(DllPath.c_str()) + 1, MEM_COMMIT, PAGE_READWRITE);
	DWORD nBytesWritten;

	if (WriteProcessMemory(hProcess, lpDllAddress, DllPath.c_str(), strlen(DllPath.c_str()) + 1, &nBytesWritten) == 0 || nBytesWritten == 0) //if WriteProcessMemory fails the return value is zero
	{
		std::cout << "Error: WriteProcessMemory failed!, error code: " << std::hex << GetLastError() << std::endl;
		return false;
	}
	//Create the thread that runs the injected dll
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)llAddress, lpDllAddress, NULL, NULL);
	if (!hThread) {
		std::cout << "Error: CreateRemoteThread failed!, error code: " << std::hex << GetLastError() << std::endl;
		return false;
	}
	else { //it succeeded!
		CloseHandle(hThread);
	}
	
	std::cout << "Successful dll injection" << std::endl;
	return true;
}

int main(int argc, char* argv[])
{
	DWORD ProcessID;
	while (1)
	{
		std::cout << "Enter Process ID:" << std::endl;
		std::cin >> ProcessID;

		bool is_successful = InjectDLL(ProcessID);
	}
	return 0;
}

/*
* #define MSGRET(str, ret) { cout << "ERROR: " << str << endl; system("pause"); return ret; }
DWORD procNameToPID(const char *procName)
{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
				MSGRET("Unable to create snapshot.", 0)

		PROCESSENTRY32 process;
		process.dwSize = sizeof(PROCESSENTRY32);

		Process32First(snapshot, &process);
		do
		{
				if (strstr(process.szExeFile, procName))
						return process.th32ProcessID;
		}
		while (Process32Next(snapshot, &process));

		return 0;
}*/