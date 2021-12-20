#ifndef _DLL_H_
#define _DLL_H_

#pragma comment(lib,"user32.lib");

#include <windows.h>
#include<conio.h>
#include<iostream>
#include<string>

//#define TARGET_FUNCTION "WriteFile"
#define TARGET_FUNCTION "lstrcmpA"
#define TARGET_SWAP newlstrcmpA
#define IMPORT_TABLE_OFFSET 1
using namespace std;

//BOOL newWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);


DWORD sourceAddr;
//int newlstrcmpA();
int WINAPI newlstrcmpA(LPCSTR a, LPCSTR b);
bool IAThooking(HMODULE, LPCSTR, PVOID);
bool rewriteThunk(PIMAGE_THUNK_DATA pThunk, void* newFunc);
PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE);
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved);


#endif /* _DLL_H_ */