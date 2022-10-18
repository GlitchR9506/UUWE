#pragma once

namespace UUWE {
	namespace Remote {
		PPEB
		    GetPEBaddress(
                HANDLE hProcess
            );

        ULONG_PTR
            GetImageFromPEB(
                HANDLE hProc,
                PPEB pPEB
            );

        PIMAGE_NT_HEADERS64
            GetNTheader64(
                HANDLE hProc,
                ULONG_PTR imageBase,
                PIMAGE_DOS_HEADER pheaderDOS
            );
        PIMAGE_NT_HEADERS32
            GetNTheader32(
                HANDLE hProc,
                ULONG_PTR imageBase,
                PIMAGE_DOS_HEADER pheaderDOS
            );
        PIMAGE_DOS_HEADER
            GetDOSheader(
                HANDLE hProc,
                ULONG_PTR imageBase
            );
        PIMAGE_IMPORT_DESCRIPTOR
        GetImportDescriptor(
            HANDLE hProc,
            ULONG_PTR imageBase,
            DWORD dwImportTableOffset
        );
        LPCSTR*
            GetLibraryName(
                HANDLE hProc,
                ULONG_PTR imageBase,
                PIMAGE_IMPORT_DESCRIPTOR pimageImportDescriptor
            );
	}
}