#include <fltKernel.h>
#include "Globals.h"

#define PROCESS_QUERY_INFORMATION (0x0400)
#define PROCESS_VM_READ (0x0010)

PFLT_FILTER gFilterHandle = NULL;
BOOLEAN gProcessNotifyRoutineRegistered = FALSE;
typedef NTSTATUS(*ZWQUERYINFORMATIONPROCESS)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );
ZWQUERYINFORMATIONPROCESS ZwQueryInformationProcessPtr = NULL;
KSPIN_LOCK gSpinLock; // for the creation of process monitoring


NTSTATUS GetProcessImageFileName(HANDLE ProcessId, PUNICODE_STRING ImageFileName)
{
    NTSTATUS status;
    HANDLE hProcess;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    ULONG returnedLength;

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = NULL;

    status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG bufferLength = 512;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferLength, 'imgf');
    if (buffer == NULL) {
        ZwClose(hProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryInformationProcessPtr(hProcess, ProcessImageFileName, buffer, bufferLength, &returnedLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePool(buffer);
        buffer = ExAllocatePool2(POOL_FLAG_PAGED, returnedLength, 'imgf');
        if (buffer == NULL) {
            ZwClose(hProcess);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        status = ZwQueryInformationProcessPtr(hProcess, ProcessImageFileName, buffer, returnedLength, &returnedLength);
    }

    if (NT_SUCCESS(status)) {
        UNICODE_STRING imagePath;
        RtlInitUnicodeString(&imagePath, (PCWSTR)buffer);
        RtlCopyUnicodeString(ImageFileName, &imagePath);
    }

    ExFreePool(buffer);
    ZwClose(hProcess);
    return status;
}

void ProcessCreateNotify(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
)
{
    UNREFERENCED_PARAMETER(ParentId);
    if (!Create) {
        // Process is terminating, no need to check
        return;
    }

    UNICODE_STRING imageFileName;
    WCHAR buffer[512];
    imageFileName.Buffer = buffer;
    imageFileName.Length = 0;
    imageFileName.MaximumLength = sizeof(buffer);
    DbgPrint("Process Name: %wZ\n", imageFileName);
    NTSTATUS status = GetProcessImageFileName(ProcessId, &imageFileName);
    if (NT_SUCCESS(status)) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&gSpinLock, &oldIrql);

        // Check if the blacklist is not empty
        if (gBlackList.Length > 0) {

            if (RtlCompareUnicodeString(&imageFileName, &gBlackList, TRUE) == 0) {
                // Block the process creation
                PsTerminateSystemThread(STATUS_ACCESS_DENIED);
            }
        }
        else if(gWhiteList.Length > 0) {

            if (RtlCompareUnicodeString(&imageFileName, &gWhiteList, TRUE) != 0) {
                // Block the process creation
                PsTerminateSystemThread(STATUS_ACCESS_DENIED);
            }
        }
        KeReleaseSpinLock(&gSpinLock, oldIrql);
    }
}


FLT_PREOP_CALLBACK_STATUS PreCreateOperation(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo;

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);
    if (RtlCompareUnicodeString(&nameInfo->Name, &gProtectedFilePath, TRUE) == 0) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


NTSTATUS MiniFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (gProcessNotifyRoutineRegistered) {
        PsSetCreateProcessNotifyRoutine(ProcessCreateNotify, TRUE);
        gProcessNotifyRoutineRegistered = FALSE;
    }

    FltUnregisterFilter(gFilterHandle);
    return STATUS_SUCCESS;
}


const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreateOperation, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),       // Size
    FLT_REGISTRATION_VERSION,       // Version
    0,                              // Flags
    NULL,                           // Context
    Callbacks,                      // Operation callbacks
    MiniFilterUnload,               // MiniFilterUnload
    NULL,                           // InstanceSetup
    NULL,                           // InstanceQueryTeardown
    NULL,                           // InstanceTeardownStart
    NULL,                           // InstanceTeardownComplete
    NULL,                           // GenerateFileName
    NULL,                           // NormalizeNameComponent
    NULL                            // NormalizeContextCleanup
};


// Define FilterDriverEntry as extern "C" to avoid C++ name mangling
extern "C" NTSTATUS FilterDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    KdPrint(("FilterDriverEntry: Entering FilterDriverEntry\n"));

    // Get the address of ZwQueryInformationProcess
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
    ZwQueryInformationProcessPtr = (ZWQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
    if (ZwQueryInformationProcessPtr == NULL) {
        KdPrint(("FilterDriverEntry: MmGetSystemRoutineAddress for ZwQueryInformationProcess failed\n"));
        return STATUS_UNSUCCESSFUL;
    }
    

    // Register the mini-filter driver
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("FilterDriverEntry: FltRegisterFilter failed with status 0x%x\n", status));
        return status;
    }

    KdPrint(("FilterDriverEntry: Starting filtering\n"));

    // Start filtering
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("FilterDriverEntry: FltStartFiltering failed with status 0x%x\n", status));
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    // Register process creation callback
    status = PsSetCreateProcessNotifyRoutine(ProcessCreateNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("FilterDriverEntry: PsSetCreateProcessNotifyRoutine failed with status 0x%x\n", status));
        FltUnregisterFilter(gFilterHandle);
        return status;
    }
    else {
        gProcessNotifyRoutineRegistered = TRUE;
    }

    KdPrint(("FilterDriverEntry: Filter driver initialized successfully\n"));
    return STATUS_SUCCESS;
}