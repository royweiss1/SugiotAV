#include <ntddk.h>
#include "Globals.h"
extern "C" NTSTATUS FilterDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

#define IOCTL_BLACKLIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WHITELIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BLOCK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KILL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INIT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_TERMINATE (0x0001)  // Terminate the process

#define PROCESS_QUERY_INFORMATION (0x400)
#define PROCESS_VM_READ (0x0010)

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\sugiotAV");
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\??\\sugiotAVLink");

PDEVICE_OBJECT GlobalDeviceObject = NULL;


// for the dump:
typedef struct {
    ULONG PID;
    SIZE_T Bytes;
} DUMP_MEM_REQUEST;

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

NTSTATUS OpenProcessAndReference(
    HANDLE ProcessId,
    PEPROCESS* Process
) {
    NTSTATUS status;
    HANDLE ProcessHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ClientId.UniqueProcess = ProcessId;
    ClientId.UniqueThread = NULL;

    status = ZwOpenProcess(&ProcessHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &ClientId);
    if (!NT_SUCCESS(status)) {
        KdPrint(("ZwOpenProcess failed with status 0x%x\n", status));
        return status;
    }

    status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, *PsProcessType, KernelMode, (PVOID*)Process, NULL);
    ZwClose(ProcessHandle);

    if (!NT_SUCCESS(status)) {
        KdPrint(("ObReferenceObjectByHandle failed with status 0x%x\n", status));
    }

    return status;
}

extern "C" NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

NTSTATUS KeReadProcessMemory(HANDLE PID, PVOID TargetAddress, SIZE_T Size)
{
    SIZE_T Result;
    PEPROCESS SourceProcess = NULL;
    PEPROCESS TargetProcess = NULL;
    NTSTATUS status;

    status = OpenProcessAndReference(PID, &SourceProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PVOID SourceAddress = PsGetProcessSectionBaseAddress(SourceProcess);
    if (SourceAddress == NULL) {
        KdPrint(("PsGetProcessSectionBaseAddress returned NULL\n"));
        ObDereferenceObject(SourceProcess);
        return STATUS_UNSUCCESSFUL;
    }

    TargetProcess = PsGetCurrentProcess();

    __try {
        status = MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result);
        if (NT_SUCCESS(status)) {
            status = STATUS_SUCCESS;
        }
        else {
            KdPrint(("MmCopyVirtualMemory failed with status 0x%x\n", status));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Exception in KeReadProcessMemory\n"));
        status = GetExceptionCode();
    }

    if (SourceProcess) {
        ObDereferenceObject(SourceProcess);
    }

    return status;
}


NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObjectLocal, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObjectLocal);
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR Information = 0;

    ULONG ControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID InputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

    switch (ControlCode) //recieved messege
    {
    case IOCTL_BLACKLIST:
        if (InputBufferLength >= sizeof(WCHAR) && InputBuffer != NULL) {
            status = SetBlackList((PCWSTR)InputBuffer);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_WHITELIST:
        if (InputBufferLength >= sizeof(WCHAR) && InputBuffer != NULL) {
            status = SetWhiteList((PCWSTR)InputBuffer);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_BLOCK: 
        if (InputBufferLength >= sizeof(WCHAR) && InputBuffer != NULL) {
            
            status = SetProtectedFilePath((PCWSTR)InputBuffer);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_DUMP:
        KdPrint(("Dump IOCTL has been received.\n"));
        if (InputBufferLength == sizeof(DUMP_MEM_REQUEST) && OutputBufferLength > 0)
        {
            DUMP_MEM_REQUEST* memReq = (DUMP_MEM_REQUEST*)InputBuffer;
            if (memReq->Bytes <= OutputBufferLength)
            {
                status = KeReadProcessMemory((HANDLE)memReq->PID, OutputBuffer, memReq->Bytes);

                if (NT_SUCCESS(status))
                {
                    Information = memReq->Bytes;
                }
                else
                {
                    KdPrint(("KeReadProcessMemory failed with status 0x%x\n", status));
                    status = STATUS_UNSUCCESSFUL;
                }
            }
            else
            {
                KdPrint(("Requested byte size exceeds output buffer length\n"));
                status = STATUS_BUFFER_TOO_SMALL;
            }
        }
        else
        {
            KdPrint(("Invalid parameter - size of DUMP_MEM_REQUEST\n"));
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_KILL:
        if (InputBufferLength == sizeof(ULONG) && OutputBufferLength == sizeof(BOOLEAN))
        {
            ULONG PidToKill = *(ULONG*)InputBuffer;
            HANDLE ProcessHandle;
            OBJECT_ATTRIBUTES ObjectAttributes;
            CLIENT_ID ClientId;

            InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
            ClientId.UniqueProcess = (HANDLE)PidToKill;
            ClientId.UniqueThread = NULL;

            status = ZwOpenProcess(&ProcessHandle, PROCESS_TERMINATE, &ObjectAttributes, &ClientId);

            if (NT_SUCCESS(status))
            {
                // Terminate the process - NtTerminateProcess is undocumented
                status = ZwTerminateProcess(ProcessHandle, STATUS_SUCCESS);
                ZwClose(ProcessHandle);

                if (NT_SUCCESS(status))
                {
                    *(BOOLEAN*)OutputBuffer = TRUE; // Indicate success
                    Information = sizeof(BOOLEAN);
                }
                else
                {
                    *(BOOLEAN*)OutputBuffer = FALSE; // Indicate failure
                    Information = sizeof(BOOLEAN);
                }
            }
            else
            {
                *(BOOLEAN*)OutputBuffer = FALSE; // Indicate failure
                Information = sizeof(BOOLEAN);
            }
        }
        else
        {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_INIT:
        status = InitializePaths();

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    KdPrint(("completed switch case\n"));
    return status;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // do stuff to clean:
    CleanupPaths(); // string cleanup

    IoDeleteSymbolicLink(&SymLinkName);
    IoDeleteDevice(GlobalDeviceObject);
}

NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        break;
    case IRP_MJ_CLOSE:
        break;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    KdPrint(("Entering Drive Entery\n"));

    status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &GlobalDeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(GlobalDeviceObject);
        return status;
    }

    // Register the mini-filter driver
    status = FilterDriverEntry(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        KdPrint(("DriverEntry: FilterDriverEntry failed with status 0x%x\n", status));
        IoDeleteSymbolicLink(&SymLinkName);
        IoDeleteDevice(GlobalDeviceObject);
        return status;
    }
    KdPrint(("DriverEntry: Driver loaded successfully\n"));


    return STATUS_SUCCESS;
}