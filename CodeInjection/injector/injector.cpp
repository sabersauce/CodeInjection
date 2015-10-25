//exec
//injector

//using WinExec()

#include <Windows.h>
#include <stdio.h>

char path[MAX_PATH];

typedef struct _param {
	FARPROC pFunc;
	char szParam[MAX_PATH];
	UINT uiParam;
	
}*pParam, PARAM;

typedef FARPROC (WINAPI *pWinExec)(LPCSTR, UINT);

DWORD WINAPI
ThreadProc(LPVOID lParam) {
	pParam p = (pParam)lParam;
	((pWinExec)(p->pFunc))((LPCSTR)p->szParam,p->uiParam);
	return 0;
}

BOOL
InjectCode(DWORD pID) {
	PARAM param;
	HMODULE hMod = GetModuleHandleA("kernel32.dll");
	param.pFunc = GetProcAddress(hMod, "WinExec");
	strcpy(param.szParam, path);
	param.uiParam = SW_SHOWNORMAL;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (hProcess == NULL) {
		printf("Open process error.\n");
		return FALSE;
	}

	DWORD bufSize = sizeof(_param);
	DWORD bytesWritten = 0;
	LPVOID pRemoteParam = VirtualAllocEx(hProcess, NULL, bufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteParam == NULL) {
		printf("Memory allocation at remote process failed.\n");
		CloseHandle(hProcess);
		return FALSE;
	}
	if (WriteProcessMemory(hProcess, pRemoteParam, (LPVOID)&param, bufSize, &bytesWritten) == 0 || bytesWritten != bufSize) {
		printf("Write remote process memory error.\n");
		CloseHandle(hProcess);
		return FALSE;
	}

	bufSize = 100;
	bytesWritten = 0;
	LPVOID pRemoteProc = VirtualAllocEx(hProcess, NULL, bufSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pRemoteParam == NULL) {
		printf("Memory allocation at remote process failed.\n");
		CloseHandle(hProcess);
		return FALSE;
	}
	if (WriteProcessMemory(hProcess, pRemoteProc, (LPVOID)ThreadProc, bufSize, &bytesWritten) == 0 || bytesWritten != bufSize) {
		printf("Write remote process memory error.\n");
		CloseHandle(hProcess);
		return FALSE;
	}
	
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteProc, pRemoteParam, 0, NULL);
	if (hThread == NULL) {
		printf("Create remote thread failed.\n");
		CloseHandle(hProcess);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	
	return TRUE;
}

int
main(int argc, char *argv[]) {
	if (argc != 3) {
		if (argc != 1) printf("Wrong parameters.\n\n");
		printf("Usage:injector.exe <ProcessID> <FileToExcute>\n");
	}

	strcpy(path, argv[2]);
	int pID = atoi(argv[1]);

	if (InjectCode(pID)) {
		printf("Injection complete successfully.\n");
		return 0;
	}
	else {
		printf("Inject failed.\n");
		return -1;
	}
}