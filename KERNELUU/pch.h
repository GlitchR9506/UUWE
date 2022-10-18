// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <winternl.h>
#include <algorithm>
#include <cctype>
#include <string>
#include <map>


typedef NTSTATUS(NTAPI* tyfn_NtQueryInformationProcess)(
    IN   HANDLE ProcessHandle,
    IN   PROCESSINFOCLASS ProcessInformationClass,
    OUT  PVOID ProcessInformation,
    IN   ULONG ProcessInformationLength,
    OUT  PULONG ReturnLength OPTIONAL
    );

#define format_as_string(...) #__VA_ARGS__


#include "uuwe.hxx"
#include "PEB_stuff.h"

#endif //PCH_H
