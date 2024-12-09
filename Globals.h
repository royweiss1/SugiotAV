#ifndef GLOBALS_H
#define GLOBALS_H

#include <ntddk.h>  // Ensure you include necessary headers

extern UNICODE_STRING gProtectedFilePath;
extern UNICODE_STRING gWhiteList;
extern UNICODE_STRING gBlackList;

NTSTATUS SetProtectedFilePath(PCWSTR path);
NTSTATUS SetWhiteList(PCWSTR path);
NTSTATUS SetBlackList(PCWSTR path);

NTSTATUS InitializePaths();
void CleanupPaths();

#endif // GLOBALS_H