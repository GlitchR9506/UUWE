#pragma once
#include "pch.h"

namespace UUWE {
	namespace Remote {
        PPEB
		GetPEBaddress(
			HANDLE hProc
		)
			//
			// Gets address of PEB pf specified process
			//
		{
            ///////////////////////////////////
            ////
            //// Load NtQueryInformationProcess
            ////
            tyfn_NtQueryInformationProcess _NtQueryInformationProcess;
            HMODULE hNTDLL = LoadLibraryA("NTDLL.DLL");
            if (hNTDLL == NULL) {
                printf("UNABLE TO LOAD NTDLL");
                return (PPEB)(-1);
            }
            else {
                _NtQueryInformationProcess = (tyfn_NtQueryInformationProcess)GetProcAddress(hNTDLL, "NtQueryInformationProcess");
                if (_NtQueryInformationProcess == NULL) {
                    printf("UNABLE TO LOAD NtQueryInformationProcess");
                    return (PPEB)(-1);
                }
            }

            ///////////////////////////////////
            ////
            //// Grab PEB from PBI
            ////
            PROCESS_BASIC_INFORMATION pPBI;// = new PROCESS_BASIC_INFORMATION();
            DWORD returnLength = 0;
            NTSTATUS Status = _NtQueryInformationProcess(
                hProc,
                ProcessBasicInformation,    // enum of 0
                &pPBI,
                sizeof(pPBI),
                &returnLength
            );

            if (!NT_SUCCESS(Status)) {
                printf("NtQueryInformationProcess failed with status of [%i]", Status);
                return (PPEB)(-1);
            }


            return pPBI.PebBaseAddress;

		}

        ULONG_PTR
            GetImageFromPEB(
                HANDLE hProc,
                PPEB pPEB
            ) {
            PEB peb;

            if (ReadProcessMemory(hProc, (PVOID)pPEB, &peb, sizeof(peb), NULL) == 0) {
                printf("ReadProcessMemory FAILED [%i]\r\n", GetLastError());
                return ULONG_PTR(-1);
            }
            else {
                printf("ReadProcessMemory SUCCEDDED\r\n");

            }
            return (ULONG_PTR)peb.ImageBaseAddress;
        }

        PIMAGE_DOS_HEADER
            GetDOSheader(
                HANDLE hProc,
                ULONG_PTR imageBase
            ) 
            //
            // Now working
            //
        {
            IMAGE_DOS_HEADER headerDOS;

            if (!ReadProcessMemory(
                hProc,
                (PVOID)imageBase,
                &headerDOS,
                sizeof(headerDOS),
                0))
            {
                printf("Failed to read DOS header\r\n");
            }
            else {
                printf("Read DOS header Successfully @[%i{0x%X}]\r\n",&headerDOS,&headerDOS);
            }
            return &headerDOS;
        }

        PIMAGE_NT_HEADERS64
            GetNTheader64(
                HANDLE hProc,
                ULONG_PTR imageBase,
                PIMAGE_DOS_HEADER pheaderDOS
            ) 
            //
            // Gives wrong address
            // // SCRATCH THAT,
            // // IT WORKS
            // // imageBase needed to be a ULONG_PTR, changed and fixed
            //
        
        {
            IMAGE_NT_HEADERS64 headerNT;
            if (!ReadProcessMemory(
                hProc,
                (PVOID)(imageBase + pheaderDOS->e_lfanew),
                &headerNT,
                sizeof(headerNT),
                0)) {
                printf("Failed to read PE64 header GetLastError[%i]\r\n", GetLastError());
            }
            else {
                printf("Read PE64 header Successfully @[%i{0x%X}]\r\n", &headerNT, &headerNT);

            }
            //PIMAGE_NT_HEADERS pheaderNT = (PIMAGE_NT_HEADERS)((LPBYTE)imageBase + pheaderDOS->e_lfanew);

            return &headerNT;
        }

        PIMAGE_NT_HEADERS32
            GetNTheader32(
                HANDLE hProc,
                ULONG_PTR imageBase,
                PIMAGE_DOS_HEADER pheaderDOS
            )
            //
            // Doesnt work
            //

        {
            IMAGE_NT_HEADERS32 headerNT;
            if (!ReadProcessMemory(
                hProc,
                (PVOID)((DWORD_PTR)imageBase + pheaderDOS->e_lfanew),
                &headerNT,
                sizeof(headerNT),
                0)) {
                printf("Failed to read PE32 header GetLastError[%i]\r\n", GetLastError());
            }
            else {
                printf("Read PE32 header Successfully @[%i{0x%X}]\r\n", &headerNT, &headerNT);

            }
            //PIMAGE_NT_HEADERS pheaderNT = (PIMAGE_NT_HEADERS)((LPBYTE)imageBase + pheaderDOS->e_lfanew);

            return &headerNT;
        }

        PIMAGE_IMPORT_DESCRIPTOR
            GetImportDescriptor(
                HANDLE hProc,
                ULONG_PTR imageBase,
                DWORD dwImportTableOffset
            ) {
            IMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
            if (!ReadProcessMemory(
                hProc,
                (PVOID)(imageBase + dwImportTableOffset),
                &imageImportDescriptor,
                sizeof(imageImportDescriptor),
                0)) {
                printf("Failed to read IAT GetLastError[%i]\r\n", GetLastError());
            }
            else {
                //printf("Read IAT Successfully @[%i{0x%X}]\r\n", &imageImportDescriptor, &imageImportDescriptor);

            }

            return &imageImportDescriptor;
        }
        LPCSTR*
            GetLibraryName(
                HANDLE hProc,
                ULONG_PTR imageBase,
                PIMAGE_IMPORT_DESCRIPTOR pimageImportDescriptor
            ) {
            LPCSTR libraryName;
            if (!ReadProcessMemory(
                hProc,
                (PVOID)(imageBase + pimageImportDescriptor->Name),
                &libraryName,
                sizeof(libraryName),
                0)) {
                printf("Failed to read libraryName GetLastError[%i]\r\n", GetLastError());
            }
            else {
                LPCSTR* p_libraryName = &libraryName;
                printf("Read libraryName[%s] Successfully \r\n", *libraryName);

            }

            return &libraryName;
        }
	}
}