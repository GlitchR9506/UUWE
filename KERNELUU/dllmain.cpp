// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"


//
// Defines 
// 
#define __MODULE__ "KERNELUU.DLL"
#include <uwe.hxx>
#define IMPLEMENT_FUNCTION printf("\t[%s:%s] Called\r\n", __MODULE__, __FUNCTION__);

#define STRING(str) #str 
#if !defined(__PRETTY_FUNCTION__) && !defined(__GNUC__)
#define __PRETTY_FUNCTION__ __FUNCSIG__
#endif
#define GETFUNC() ""
#define GETLINE() STRING(__LINE__)

#define COMMA ,
#define LogMsgEx(code, format, ...)  \
    SYSTEMTIME st, lt, dt; \
	GetSystemTime(&st); \
	GetLocalTime(&lt);  \
	dt = et;\
	dt = st - et;\
	/*LogMsgNaked("[%s][UUWELDR:"GETFUNC()"{line:%i}] \r\n  @ LOCAL[%02d:%02d:%02d] : UTC[%02d:%02d:%02d] : ELAPSED[%02d:%02d:%02d]\r\n\r\n\t"format,#code,__LINE__,  lt.wHour, lt.wMinute, lt.wSecond, st.wHour, st.wMinute, st.wSecond, dt.wHour, dt.wMinute, dt.wSecond, __VA_ARGS__); */\
	printf("[%s][UUWELDR:"GETFUNC()"{line:%i}] \r\n  @ LOCAL[%02d:%02d:%02d] : UTC[%02d:%02d:%02d] : ELAPSED[%02d:%02d:%02d]\r\n\r\n\t"format,#code,__LINE__,  lt.wHour, lt.wMinute, lt.wSecond, st.wHour, st.wMinute, st.wSecond, dt.wHour, dt.wMinute, dt.wSecond, __VA_ARGS__)

namespace UUWE {
    BOOLEAN
        StringInsensitiveEquals(std::string a, std::string b) {

        std::transform(a.begin(), a.end(), a.begin(),
            [](unsigned char c) { return std::tolower(c); });
        std::transform(b.begin(), b.end(), b.begin(),
            [](unsigned char c) { return std::tolower(c); });

        if (a == b) {
            return true;
        }
        return false;
    }
}

HMODULE g_hMod;

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {

    g_hMod = hModule;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


/*Convert Virtual Address to File Offset */
DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
    size_t i = 0;
    PIMAGE_SECTION_HEADER pSeh;
    if (rva == 0)
    {
        return (rva);
    }
    pSeh = psh;
    for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
    {
        if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
            pSeh->Misc.VirtualSize)
        {
            break;
        }
        pSeh++;
    }
    return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

BOOL 
UUWE_KERNEL32__CreateProcessA(
    LPCSTR 	lpApplicationName,
    LPSTR 	lpCommandLine,
    LPSECURITY_ATTRIBUTES 	lpProcessAttributes,
    LPSECURITY_ATTRIBUTES 	lpThreadAttributes,
    BOOL 	bInheritHandles,
    DWORD 	dwCreationFlags,
    LPVOID 	lpEnvironment,
    LPCSTR 	lpCurrentDirectory,
    LPSTARTUPINFOA 	lpStartupInfo,
    LPPROCESS_INFORMATION 	lpProcessInformation
) {
    IMPLEMENT_FUNCTION

    BOOLEAN bStatus;


    //
    // Create
    //
    bStatus = CreateProcessA(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        //CREATE_SUSPENDED,//dwCreationFlags, // should it be "    dwCreationFlags | CREATE_SUSPENDED,    "?
        dwCreationFlags | CREATE_SUSPENDED,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
    if (!bStatus) {
        //
        // Uh-Oh
        // Log-'n'-Ret
        //
        printf("CREATEPROCESS AS SUSPENDED FAILED [%i]\r\n",GetLastError());
        return FALSE;
    }

    HANDLE hProc = lpProcessInformation->hProcess;


    ////
    //// ReWrite imports table
    ////

    //
    // Get PEB 
    //
    PPEB pPEB = UUWE::Remote::GetPEBaddress(hProc);
    if (pPEB <= 0) {
        printf("Failed to get PEB.\r\n");
    }

    //
    // Extract image base
    //
    ULONG_PTR imageBase = UUWE::Remote::GetImageFromPEB(hProc, pPEB);
    printf("ImageBaseAddress is [%i{0x%X}]\r\n", imageBase, imageBase);

    // TEMP TEMP TEST TEST
    //hProc = g_hMod;
    /////imageBase = 0;


    //
    // Get DOS Header
    //
    PIMAGE_DOS_HEADER pheaderDOS = UUWE::Remote::GetDOSheader(hProc, imageBase);// = (PIMAGE_DOS_HEADER)imageBase;

    //
    // Check Bitness
    //
    DWORD dwImportTableOffset;
    PIMAGE_NT_HEADERS32 pheaderNT32;// = UUWE::Remote::GetNTheader32(hProc, imageBase, pheaderDOS);
    PIMAGE_NT_HEADERS64 pheaderNT64 = UUWE::Remote::GetNTheader64 (hProc, imageBase, pheaderDOS);
    
    //
    // :TROLL_FACE:
    // Hey, if its the only way it works its the only way it works
    //
    PVOID pheaderAddress = (PVOID)(pheaderNT64);
    pheaderNT32 = (PIMAGE_NT_HEADERS32)pheaderAddress;
    

    if (pheaderNT64->OptionalHeader.Magic != 0x010B) {
        dwImportTableOffset = ((IMAGE_OPTIONAL_HEADER64)pheaderNT64->OptionalHeader).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        printf("Specified binary is not PE32, assuming is PE64\r\n");
    }
    else {
        dwImportTableOffset = ((IMAGE_OPTIONAL_HEADER32)pheaderNT32->OptionalHeader).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        printf("Specified binary is PE32\r\n");
    }
    //LPVOID imageBase = GetModuleHandleA(NULL);
    //PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    //PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

    //
    // Get import table address
    //

    if (dwImportTableOffset == 0) {
        printf("Does not contain import address table, is NTDLL?\r\n");
        //goto Failed;
    } else {
        printf("Found IAT\r\n");
        
    }


    //
    // Get Import Descriptor
    //
    PIMAGE_IMPORT_DESCRIPTOR pimageImportDescriptor = UUWE::Remote::GetImportDescriptor(hProc, imageBase, dwImportTableOffset);

    char towriteName[MAX_PATH] = "KERNELUU.dll";

    //ULONG_PTR count = 0;


    //
    // 17th October - 2022  :  
    //  Can only get one entry - dont know why
    // It starts reading data at the beginning of the file after that (why?)
    // FIXED - SAME DAY
    //
    for(int countEntries = 0; pimageImportDescriptor->OriginalFirstThunk != 0; ++countEntries) {

        //
        // Get appropriate import descriptor
        //
        pimageImportDescriptor = UUWE::Remote::GetImportDescriptor(hProc, imageBase, dwImportTableOffset + (sizeof(IMAGE_IMPORT_DESCRIPTOR) * countEntries));

        //  Adding 338 to the value of pimageImportDescriptor will change from KERNEL32 to GDI32
        // 188912 + 338 = 189250, the location of GDI32 is not present in the memory of the import descriptor, so something is wrong with it
        // former is mentioned at 179404
        // latter is mentioned at 179424
        // this is a different of 20 bytes
        // or 0x14 bytes
        // aka the size of an IMAGE_IMPORT_DESCRIPTOR
        // so 179404-0x10 should be the beginning of the IMAGE_IMPORT_DESCRIPTOR array
        // 
        // AHAHAHA
        // 
        // 10/17/2022 9:22PM IT WORKS
        // 
        //pimageImportDescriptor = UUWE::Remote::GetImportDescriptor(hProc, imageBase, dwImportTableOffset + (sizeof(IMAGE_IMPORT_DESCRIPTOR) * countEntries));
        // the `dwImportTableOffset + (sizeof(IMAGE_IMPORT_DESCRIPTOR) * countEntries)` is the key instead of `dwImportTableOffset + countEntries)`
        // 

        //
        // Grab the DLL Name
        //

        //
        // I should be able to grab pimageImportDescriptor->Name into a DWORD -- as it is stored
        // and treat it as a pointer
        //
        ULONG_PTR addressName = pimageImportDescriptor->Name;

        char   libraryName[MAX_PATH];
        if (!ReadProcessMemory(
            hProc,
            (PVOID)(addressName + imageBase),
            &libraryName,
            sizeof(libraryName),
            0)) {
            printf("Failed to read libraryName - GetLastError[%i]\r\n", GetLastError());
            break;
        }
        else {
            //LPCSTR* p_libraryName = &libraryName;
            printf("\t\tFound Library[%s] \r\n", libraryName);
            //printf("\t\tFound Library[%s] [%i{0x%X}] \r\n", libraryName, (pimageImportDescriptor->Name), (pimageImportDescriptor->Name));

        }
        DWORD plibraryName;
        if (!ReadProcessMemory(
            hProc,
            (PVOID)((ULONG_PTR)addressName + imageBase),
            &plibraryName,
            sizeof(plibraryName),
            0)) {
            printf("Failed to read plibraryName - GetLastError[%i]\r\n", GetLastError());
        }
        else {
            //LPCSTR* p_libraryName = &libraryName;
            printf("\t\tFound Pointer to Library Name @[%i{0x%X}] \r\n", plibraryName, plibraryName);
            //printf("\t\tFound Library[%s] [%i{0x%X}] \r\n", libraryName, (pimageImportDescriptor->Name), (pimageImportDescriptor->Name));

        }
        



        //
        // TODO 
        // Implement redirecting imports and ordinals aswell as entire dlls
        //
        std::map<std::string, std::string> listDllsToRewrite;
        listDllsToRewrite["KERNEL32.DLL"] = "KERNELUU.DLL";
        //listDllsToRewrite["SHELL32.DLL"]  = "SHELLUU.DLL";

        //
        // Convert to std::string
        //
        std::string curDLL = std::string(libraryName);

        //
        // Uppercase it
        //
        std::transform(curDLL.begin(), curDLL.end(), curDLL.begin(),
            [](unsigned char c) { return std::toupper(c); });


        if (listDllsToRewrite.count(curDLL)) {

            //
            // Get location that libraryName is stored at and write to it
            //

            ULONG_PTR	ulDst = ULONG_PTR((addressName) + imageBase);
            LPCSTR		lpSrc = listDllsToRewrite[curDLL].c_str();
            SIZE_T      nSize = strlen(lpSrc) + 1;
            DWORD       dwOldProtect;

            printf("\t\t   Rewriting Library[%s] ->[%s] \r\n", libraryName, lpSrc);
            //printf("\t\t   Writing at address [%i{0x%X}] [%i{0x%X}] \r\n", ulDst, ulDst, ulDst - imageBase, ulDst - imageBase); 
            printf("\t\t   Writing at address [%i{0x%X}] [%i{0x%X}] \r\n", ulDst, ulDst, pimageImportDescriptor->Name, pimageImportDescriptor->Name); //plibraryName

            for (int i = 0; i < listDllsToRewrite[curDLL].length(); i++) {
                if (VirtualProtectEx(
                    hProc,
                    (PVOID)(ulDst + i),
                    sizeof(CHAR),
                    PAGE_EXECUTE_READWRITE,
                    &dwOldProtect
                ) == FALSE) {
                    printf("Failed to set access protections on process: %i\r\n", GetLastError());
                    goto NextImport;
                }
                CHAR a = 's';
                if (WriteProcessMemory(
                    hProc,
                    (PVOID)(ulDst + i),
                    &listDllsToRewrite[curDLL][i],
                    sizeof(CHAR),
                    NULL
                ) == FALSE) {
                    printf("Failed to write process memory at offset %p with %llu bytes of data: %i\r\n",
                        ulDst, nSize, GetLastError());
                    //    goto NextImport;
                }

                if (VirtualProtectEx(
                    hProc,
                    (PVOID)(ulDst + i),
                    sizeof(CHAR),
                    dwOldProtect,
                    &dwOldProtect
                ) == FALSE) {
                    printf("Failed to un-set access protections on process: %i\r\n", GetLastError());
                    goto NextImport;
                }
                else {
                    printf("Rewrite successful\r\n");
                }
            }

        }

    NextImport:
        continue;
        //break;
        //count++;
        //pimageImportDescriptor++;
        //pimageImportDescriptor = UUWE::Remote::GetImportDescriptor(hProc, imageBase, dwImportTableOffset + (sizeof(IMAGE_IMPORT_DESCRIPTOR) * countEntries));
        //pimageImportDescriptor = UUWE::Remote::GetImportDescriptor(hProc, imageBase, dwImportTableOffset )+count;
    }

    ////////////
    // Print out final DLL import list
    //
    for (int countEntries = 0; pimageImportDescriptor->FirstThunk != 0; ++countEntries) {

        pimageImportDescriptor = UUWE::Remote::GetImportDescriptor(hProc, imageBase, dwImportTableOffset + (sizeof(IMAGE_IMPORT_DESCRIPTOR) * countEntries));

        char libraryName[MAX_PATH];
        if (!ReadProcessMemory(
            hProc,
            (PVOID)(pimageImportDescriptor->Name + imageBase),
            &libraryName,
            sizeof(libraryName),
            0)) {
            printf("Failed to read libraryName - GetLastError[%i]\r\n", GetLastError());
            break;
        }
        else {
            //LPCSTR* p_libraryName = &libraryName;
            printf("\t\tProgram To Load[%s] \r\n", libraryName);

        }
    }
    
Failed:
    //
    // Resume
    //
    ResumeThread(lpProcessInformation->hThread);
    ///WaitForSingleObject(lpProcessInformation->hProcess, INFINITE);

    //
    // Return
    //
    return TRUE;
}

//
// Temp hardcode to report latest windows 11 version
//
BOOL
UUWE_KERNEL32__GetVersionExW(
    OUT LPOSVERSIONINFOW lpVersionInformation
) {
    IMPLEMENT_FUNCTION
    
    if (GetVersionExW(lpVersionInformation)) {
        lpVersionInformation->dwMajorVersion   = 5;
        lpVersionInformation->dwMinorVersion   = 1;
        lpVersionInformation->dwBuildNumber    = 2600;
        lpVersionInformation->dwPlatformId     = VER_PLATFORM_WIN32_NT;
        
        //
        // do OSVERSIONINFOEXW stuff
        //
        if (
            lpVersionInformation->dwOSVersionInfoSize
            == sizeof(OSVERSIONINFOEXW)
        ) {
            ((LPOSVERSIONINFOEXW)lpVersionInformation)->wServicePackMajor = 0;
            ((LPOSVERSIONINFOEXW)lpVersionInformation)->wServicePackMinor = 0;
        }
        return TRUE;
    }

    return FALSE;
}

FARPROC
UUWE_KERNEL32__GetProcAddress(
    HMODULE hModule,
    LPCSTR  lpProcName
) {
    IMPLEMENT_FUNCTION;
    printf("\t%s", lpProcName);
    MessageBoxA(
        NULL,
        lpProcName,
        __MODULE__,
        MB_OK
    );

    return GetProcAddress(hModule, lpProcName);

}