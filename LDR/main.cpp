

//
// Library Headers
//
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <windows.h>
#include <iostream>
#include <string>
//#include <processenv.h>

#define __MODULE__ "UUWELDR"
#include <uwe.hxx>
//
// Local Headers
//
SYSTEMTIME operator-(const SYSTEMTIME& pSr, const SYSTEMTIME& pSl)
{
	SYSTEMTIME t_res;
	FILETIME v_ftime;
	ULARGE_INTEGER v_ui;
	__int64 v_right, v_left, v_res;
	SystemTimeToFileTime(&pSr, &v_ftime);
	v_ui.LowPart = v_ftime.dwLowDateTime;
	v_ui.HighPart = v_ftime.dwHighDateTime;
	v_right = v_ui.QuadPart;

	SystemTimeToFileTime(&pSl, &v_ftime);
	v_ui.LowPart = v_ftime.dwLowDateTime;
	v_ui.HighPart = v_ftime.dwHighDateTime;
	v_left = v_ui.QuadPart;

	v_res = v_right - v_left;

	v_ui.QuadPart = v_res;
	v_ftime.dwLowDateTime = v_ui.LowPart;
	v_ftime.dwHighDateTime = v_ui.HighPart;
	FileTimeToSystemTime(&v_ftime, &t_res);
	return t_res;
}
//
// Structs
//

typedef struct MODINFO {
	HMODULE       hMod;			// Module Handle
	std::string   exec;			// Path of executable
	
} MODINFO, *PMODINFO;

//
// types
//
typedef BOOLEAN (*tyfn_CreateProcessA)( LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION );

typedef int (*tyfn_LDR_exec)();
typedef tyfn_LDR_exec(*tyfn_GetExecFunc)();

typedef void (*tyfn_NotifyExecFunc)();

//
// Globals
//
MODINFO Kernel32;
MODINFO UUWE_KERNEL32;

SYSTEMTIME et; // Elapsed time

//
// Function Declarations
//

int GetElapsedTime(SYSTEMTIME* lp_timeToSet, const SYSTEMTIME timeDiff);


//
// Function Definitions
//

INT
main (
	INT   argc,
	PCHAR argv[]
) {
	//
	// Start count
	//
	GetSystemTime(&et);
	printf("STARTING @UTC[%02d:%02d:%02d]\r\n", et.wHour, et.wMinute, et.wSecond);
	printf("\t (AWUU) All Windows Users' Utils\r\n");
	printf("\t (UWE)  Universal Windows Extender\r\n");
	printf("\t (UUWE) Usermode Universal Windows Extender\r\n\r\n");
	printf("\t DVER [%s]  :  RVER [%s]\r\n", DVER, RVER);
	printf("\r\n\r\n\r\n");
	//
	// Init globals
	//
	Kernel32.exec = "kernel32.dll";
	UUWE_KERNEL32.exec = "kerneluu.dll";

	DWORD ret;
	CHAR bufferPath[MAX_PATH];
	
	//
	// Is this needed?
	//
	///Kernel32.hMod = LoadLibraryA(Kernel32.exec.c_str());
	
	//
	// Load Dll
	//
	UUWE_KERNEL32.hMod = LoadLibraryA(UUWE_KERNEL32.exec.c_str());
	if (UUWE_KERNEL32.hMod == NULL) {
		LogMsgEx(
			MSGLVL_LCLFATAL,
			"LoadLibrary on [%s] returned \r\n\t lasterrorval:[%i{0x%X}]\r\n",
			UUWE_KERNEL32.exec.c_str(),
			GetLastError(),
			GetLastError()
			);
		return -1;
	}
	
	
	//
	// Future (If applicable):
	//  Call init
	//
	
	////
	//// Continue Loading
	////
	
	//
	// Get environment variable "UUWEINJECTOR_TOCALL"
	//
	ret = GetEnvironmentVariableA(
		"UUWEINJECTOR_TOCALL",
		bufferPath,
		MAX_PATH
		);
	
	//
	// Check if succedded
	//
	
	if (ret < 1) {
		//
		// If empty set as "%windir%\\System32\\winlogin.exe" (renamed winlogon)
		//
		///strcpy(bufferPath, "%windir%\\System32\\winlogin.exe");
		//strcpy(bufferPath, "C:\\Windows\\notepad.exe");
		strcpy(bufferPath, "C:\\Users\\glitch\\Downloads\\npp.8.4.6.Installer.x64.exe");
		LogMsgEx(
			MSGLVL_DEFAULTING,
			"%s\r\n\t%s\r\n",
			"Environment Variable \"UUWEINJECTOR_TOCALL\" not set, setting to default:",
			bufferPath
		);
		///bufferPath = "%windir%\\System32\\winlogin.exe";
	}
	else {
		LogMsgEx(
			MSGLVL_FINE,
			"%s\r\n\t\"%s\"\r\n",
			"Environment Variable \"UUWEINJECTOR_TOCALL\" set, calling:",
			bufferPath
		);
	}
	if ( (GetLastError() != ERROR_ENVVAR_NOT_FOUND) && ret < 1) {
		//
		// Log any oddities
		// make this a macro???
		//
		LogMsgEx(
			MSGLVL_WEIRD,
			"GetEnvironmentVariableA returned non-\"ERROR_ENVVAR_NOT_FOUND\"[%i{0x%X}] value\r\n\tGetEnvironmentVariableA retval:[%i{0x%X}]\r\n",
			//
			// [WEIRD][UUWELDR:main{l:76}] GetEnvironmentVariableA returned non-"ERROR_ENVVAR_NOT_FOUND"[203{0xCB}] value
			//     GetEnvironmentVariableA retval:[0{0x0}]
			//
			ERROR_ENVVAR_NOT_FOUND,
			ERROR_ENVVAR_NOT_FOUND,
			ret,
			ret
			);
	}
	
	
	
	//
	// Create process
	//
	
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );


	tyfn_CreateProcessA _CreateProcessA = (tyfn_CreateProcessA)GetProcAddress(UUWE_KERNEL32.hMod, "CreateProcessA");
	if (_CreateProcessA != NULL) {
		_CreateProcessA(
			bufferPath,
			(LPSTR)argv,
			NULL,
			NULL,
			FALSE,
			0,
			NULL,
			NULL,
			&si,
			&pi
		);
		//
		// Should never happen
		//
		LogMsgEx(
			MSGLVL_FINE,
			"Created specified process [%s]\r\n",
			bufferPath
		);
	} else {
		//
		// Should never happen
		//
		LogMsgEx(
			MSGLVL_LCLFATAL,
			"%s\r\n",
			"Unable to locate CreateProcessA in kerneluu.dll"
		);
	}
	
	//
	// return
	//
	//return 0;
	
	LogMsgEx(
		MSGLVL_FINE,
		"%s\r\n",
		"Starting Logging"
	);
	while (1) {
		//
		// Print log from uuwe.dll
		//
	}

	/*
	//
	// no, don't
	//
	while (1) 
		//
		// We can execute as priviledged user through this
		//
	{
		//
		// Get Function to return pointer to function execute
		//
		tyfn_GetExecFunc GetExecFunc = (tyfn_GetExecFunc)GetProcAddress(UUWE_KERNEL32.hMod, "LDR_GetExec");
		if (GetExecFunc == NULL) {
			continue;
		}
		
		//
		// Get function pointer to function to execute
		//
		tyfn_LDR_exec FunctionToCall = GetExecFunc();
		if (FunctionToCall == NULL) {
			continue;
		}
		
		//
		// Execute it
		//
		FunctionToCall();
		
		//
		// Get fp to notify that we did it
		//
		tyfn_NotifyExecFunc NotifyExecFunc = (tyfn_NotifyExecFunc)GetProcAddress(UUWE_KERNEL32.hMod, "LDR_CompletedExec");
		if (NotifyExecFunc == NULL) {
			continue;
		}
		
		//
		// notify
		//
		NotifyExecFunc();
	}*/
}
