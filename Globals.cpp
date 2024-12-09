#include "Globals.h"

// Define the variables
UNICODE_STRING gProtectedFilePath;
UNICODE_STRING gWhiteList;
UNICODE_STRING gBlackList;

// Function to set the protected file path
NTSTATUS SetProtectedFilePath(PCWSTR path) {
    NTSTATUS status = STATUS_SUCCESS;

    // Allocate and set the new path
    UNICODE_STRING newPath;
    RtlInitUnicodeString(&newPath, path);

    // Check if allocation was successful
    if (newPath.Buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else {
        if (gProtectedFilePath.Buffer) {
            ExFreePool(gProtectedFilePath.Buffer);
        }
        gProtectedFilePath = newPath;
    }

    return status;
}

// Function to set the whitelist
NTSTATUS SetWhiteList(PCWSTR path) {
    NTSTATUS status = STATUS_SUCCESS;

    // Allocate and set the new path
    UNICODE_STRING newPath;
    RtlInitUnicodeString(&newPath, path);

    // Check if allocation was successful
    if (newPath.Buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else {
        if (gWhiteList.Buffer) {
            ExFreePool(gWhiteList.Buffer);
        }
        gWhiteList = newPath;
    }

    return status;
}

// Function to set the blacklist
NTSTATUS SetBlackList(PCWSTR path) {
    NTSTATUS status = STATUS_SUCCESS;

    // Allocate and set the new path
    UNICODE_STRING newPath;
    RtlInitUnicodeString(&newPath, path);

    // Check if allocation was successful
    if (newPath.Buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else {
        if (gBlackList.Buffer) {
            ExFreePool(gBlackList.Buffer);
        }
        gBlackList = newPath;
    }

    return status;
}

// Initialize all paths
NTSTATUS InitializePaths() {
    RtlInitUnicodeString(&gProtectedFilePath, L"");
    RtlInitUnicodeString(&gWhiteList, L"");
    RtlInitUnicodeString(&gBlackList, L"");
    return STATUS_SUCCESS;
}

// Cleanup all paths
void CleanupPaths() {
    if (gProtectedFilePath.Buffer) {
        ExFreePool(gProtectedFilePath.Buffer);
        gProtectedFilePath.Buffer = NULL;
        gProtectedFilePath.Length = 0;
        gProtectedFilePath.MaximumLength = 0;
    }

    if (gWhiteList.Buffer) {
        ExFreePool(gWhiteList.Buffer);
        gWhiteList.Buffer = NULL;
        gWhiteList.Length = 0;
        gWhiteList.MaximumLength = 0;
    }

    if (gBlackList.Buffer) {
        ExFreePool(gBlackList.Buffer);
        gBlackList.Buffer = NULL;
        gBlackList.Length = 0;
        gBlackList.MaximumLength = 0;
    }
}
