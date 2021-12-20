#include "DLL.h"
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		IAThooking(GetModuleHandleA(NULL), TARGET_FUNCTION, TARGET_SWAP); //newlstrcmpA);
		break;
	case DLL_PROCESS_DETACH:
		IAThooking(GetModuleHandleA(NULL), TARGET_FUNCTION, (void*)sourceAddr);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return true;
}
bool IAThooking(HMODULE hInstance, LPCSTR targetFunction, PVOID newFunc)
{
	bool flag = false;

	PIMAGE_IMPORT_DESCRIPTOR importedModule;
	PIMAGE_THUNK_DATA pFirstThunk, pOriginalFirstThunk;
	PIMAGE_IMPORT_BY_NAME pFuncData;

	importedModule = getImportTable(hInstance);
	//pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hInstance, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize); - You can just call this function to get the Import Table
	while (*(WORD*)importedModule != 0) //over on the modules (DLLs)
	{
		printf("\n%s - %x:\n---------\n", (char*)((PBYTE)hInstance + importedModule->Name));//printing Module Name
		pFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)hInstance + importedModule->FirstThunk);//pointing to its IAT
		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)hInstance + importedModule->OriginalFirstThunk);//pointing to OriginalThunk
		pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hInstance + pOriginalFirstThunk->u1.AddressOfData);// and to IMAGE_IMPORT_BY_NAME
		while (*(WORD*)pFirstThunk != 0 && *(WORD*)pOriginalFirstThunk != 0) //moving over IAT and over names' table
		{
			printf("%X %s\n", pFirstThunk->u1.Function, pFuncData->Name);//printing function's name and addr
			if (strcmp(targetFunction, (char*)pFuncData->Name) == 0)//checks if we are in the Target Function
			{
				printf("Hooking... \n");
				if (rewriteThunk(pFirstThunk, newFunc))
					printf("Hooked %s successfully :)\n", targetFunction);
			}
			pOriginalFirstThunk++; // next node (function) in the array
			pFuncData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hInstance + pOriginalFirstThunk->u1.AddressOfData);
			pFirstThunk++;// next node (function) in the array
		}
		importedModule++; //next module (DLL)
	}
	return false;
}

/*
__declspec( naked ) int newlstrcmpA()
{
	_asm{
		XOR eax,eax;
		RETN 8;
	}
}
*/
typedef BOOL(*WriteFuncPtr)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

BOOL newWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	MessageBoxA(NULL, "hook called", "hehe", MB_OK);
	UINT_PTR funcPtr = sourceAddr;
	WriteFuncPtr writingFunc = (WriteFuncPtr)funcPtr;
	writingFunc(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	return 0;
};

int WINAPI newlstrcmpA(LPCSTR a, LPCSTR b)
{
	MessageBoxA(NULL, "hook called", "hehe", MB_OK);
	return 0;
}

PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE hInstance)
{
	PIMAGE_DOS_HEADER dosHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
	PIMAGE_NT_HEADERS ntHeader;
	IMAGE_DATA_DIRECTORY dataDirectory;

	dosHeader = (PIMAGE_DOS_HEADER)hInstance;//cast hInstance to (IMAGE_DOS_HEADER *) - the MZ Header
	ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);//The PE Header begin after the MZ Header (which has size of e_lfanew)
	optionalHeader = (IMAGE_OPTIONAL_HEADER)(ntHeader->OptionalHeader); //Getting OptionalHeader
	dataDirectory = (IMAGE_DATA_DIRECTORY)(optionalHeader.DataDirectory[IMPORT_TABLE_OFFSET]);//Getting the import table of DataDirectory
	return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hInstance + dataDirectory.VirtualAddress);//ImageBase+RVA to import table

}
bool rewriteThunk(PIMAGE_THUNK_DATA pThunk, void* newFunc)
{
	DWORD CurrentProtect;
	DWORD junk;
	VirtualProtect(pThunk, 4096, PAGE_READWRITE, &CurrentProtect);//allow write to the page
	sourceAddr = pThunk->u1.Function;
	pThunk->u1.Function = (DWORD)newFunc; // rewrite the IAT to new function
	VirtualProtect(pThunk, 4096, CurrentProtect, &junk);//return previous premissions
	return true;
}