#pragma     warning (disable : 4514 4710 4711)
#pragma     warning (push)
#pragma     warning (disable : 4365)
#include    <Ntifs.h>
#include    <wdm.h>
#pragma     warning (pop)

#include    "../common.h"
#include    "ssde.h"

DRIVER_INITIALIZE DriverEntry;

__drv_dispatchType(IRP_MJ_CREATE) DRIVER_DISPATCH_PAGED OnCreate;
__drv_dispatchType(IRP_MJ_CLOSE) DRIVER_DISPATCH_PAGED OnClose;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH OnDeviceControl;
__drv_dispatchType_other DRIVER_DISPATCH OnOther;

DRIVER_UNLOAD OnUnload;

NTSTATUS CreateApiDevice(PDRIVER_OBJECT);
VOID DestroyApiDevice(PDRIVER_OBJECT);

NTSTATUS OnApiGetInfo(PVOID, ULONG, ULONG, ULONG*);

PSSDEWORKER Worker = NULL;
NTSTATUS WorkerResult = STATUS_SUCCESS;
ULONG ArmCount = 0;
ULONG ArmWatchdog = 0;

#pragma code_seg ("PAGE")
NTSTATUS
Worker_Delete(PSSDEWORKER* __this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG uTag = 'ssde';
    PSSDEWORKER _this = *__this;

    if (_this)
    {
        if (_this->ProductPolicyValueInfo)
        {
            ExFreePoolWithTag(
                _this->ProductPolicyValueInfo,
                uTag
            );
            _this->ProductPolicyValueInfo = NULL;
            _this->ProductPolicyValueInfoSize = 0;
        }
        if (_this->ProductOptionsKey)
        {
            ZwClose(_this->ProductOptionsKey);
            _this->ProductOptionsKey = NULL;
        }
        if (_this->ProductOptionsKeyChangeEventHandle) {
            ObDereferenceObject(_this->ProductOptionsKeyChangeEventObject);
            _this->ProductOptionsKeyChangeEventObject = NULL;

            ZwClose(_this->ProductOptionsKeyChangeEventHandle);
            _this->ProductOptionsKeyChangeEventHandle = NULL;
        }
        if (_this->UnloadEventHandle) {
            ObDereferenceObject(_this->UnloadEventObject);
            _this->UnloadEventObject = NULL;

            ZwClose(_this->UnloadEventHandle);
            _this->UnloadEventHandle = NULL;
        }
        if (_this->WorkerHandle) {
            _this->WorkerObject = NULL;

            _this->WorkerHandle = NULL;
        }
        _this->pFunc = NULL;
        ExFreePoolWithTag(_this, uTag);
        *__this = NULL;
    }

    return Status;
}
#pragma code_seg ()

#pragma code_seg ("PAGE")
VOID Worker_Work(_In_ PSSDEWORKER* __this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    PSSDEWORKER _this = *__this;
    ULONG PolicyValueType = 0;
    ULONG CiAcpCks = 0;
    ULONG ResultLength = 0;
    ULONG uTag = 'ssde';
    IO_STATUS_BLOCK IoStatusBlock;

    ArmWatchdog = 1;

    PVOID objects[2];
    objects[0] = _this->UnloadEventObject;
    objects[1] = _this->ProductOptionsKeyChangeEventObject;

    while (1)
    {
        Status = ZwQueryLicenseValue(
            &gCiAcpCksName, 
            &PolicyValueType, 
            &CiAcpCks,
            sizeof(CiAcpCks),
            &ResultLength
        );
        if (!NT_SUCCESS(Status)) {
            break;
        }
        if (PolicyValueType != REG_DWORD || ResultLength != sizeof(ULONG)) {
            Status = STATUS_OBJECT_TYPE_MISMATCH;
            break;
        }

        if (CiAcpCks == 0)
        {
            while (1) {
                Status = ZwQueryValueKey(
                    _this->ProductOptionsKey,
                    &gProductPolicyValueName,
                    KeyValuePartialInformation,
                    _this->ProductPolicyValueInfo,
                    _this->ProductPolicyValueInfoSize,
                    &ResultLength
                );
                if (NT_SUCCESS(Status)) {
                    break;
                }
                else if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL) {
#pragma warning (disable: 6387)
                    ExFreePoolWithTag(
                        _this->ProductPolicyValueInfo,
                        uTag
                    );
#pragma warning (default: 6387)
                    _this->ProductPolicyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
                        POOL_FLAG_PAGED,
                        ResultLength,
                        uTag
                    );
                    if (_this->ProductPolicyValueInfo) {
                        _this->ProductPolicyValueInfoSize = ResultLength;
                    }
                    else {
                        _this->ProductPolicyValueInfoSize = 0;
                        Status = STATUS_NO_MEMORY;
                        break;
                    }
                }
                else {
                    break;
                }
            }

            ULONG uEdit = 1;
#pragma warning (disable: 6011)
            Status = HandlePolicyBinary(
                _this->ProductPolicyValueInfo->DataLength,
                _this->ProductPolicyValueInfo->Data,
                &uEdit
            );
#pragma warning (default: 6011)
            if (!NT_SUCCESS(Status))
            {
                break;
            }
            if (!uEdit)
            {
                ArmCount++;
            }

            Status = ExUpdateLicenseData(
                _this->ProductPolicyValueInfo->DataLength,
                _this->ProductPolicyValueInfo->Data
            );
        }

        Status = ZwNotifyChangeKey(
            _this->ProductOptionsKey,
            _this->ProductOptionsKeyChangeEventHandle,
            NULL,
            NULL,
            &IoStatusBlock,
            REG_NOTIFY_CHANGE_LAST_SET,
            FALSE,
            NULL,
            0,
            TRUE
        );
        if (!NT_SUCCESS(Status))
        {
            break;
        }

        Status = KeWaitForMultipleObjects(
            2,
            objects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL
        );
        if (Status != STATUS_WAIT_1)
        {
            break;
        }
    }

    Worker_Delete(__this);

    ArmWatchdog = 2;

    WorkerResult = Status;

    PsTerminateSystemThread(STATUS_SUCCESS);
}
#pragma code_seg ()

#pragma code_seg ("PAGE")
NTSTATUS 
Worker_MakeAndInitialize(PSSDEWORKER* __this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG uTag = 'ssde';
    OBJECT_ATTRIBUTES ThreadAttribute;
    PSSDEWORKER _this = NULL;

    if (*__this)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto finalize;
    }

    _this = (PSSDEWORKER)ExAllocatePool2(
        POOL_FLAG_PAGED,
        sizeof(SSDEWORKER),
        uTag
    );
    if (_this == NULL) {
        Status = STATUS_NO_MEMORY;
        goto finalize;
    }
    *__this = _this;


    Status = ZwCreateEvent(
        &(_this->ProductOptionsKeyChangeEventHandle),
        EVENT_ALL_ACCESS,
        NULL,
        SynchronizationEvent,
        FALSE
    );
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }
    Status = ObReferenceObjectByHandle(
        _this->ProductOptionsKeyChangeEventHandle,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        &(_this->ProductOptionsKeyChangeEventObject),
        NULL
    );
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }


    Status = ZwCreateEvent(
        &(_this->UnloadEventHandle),
        EVENT_ALL_ACCESS,
        NULL,
        SynchronizationEvent,
        FALSE
    );
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }
    Status = ObReferenceObjectByHandle(
        _this->UnloadEventHandle,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        &(_this->UnloadEventObject),
        NULL
    );
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }


    OBJECT_ATTRIBUTES KeyAttribute;
    InitializeObjectAttributes(
        &KeyAttribute,
        &gProductOptionsKeyName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
    Status = ZwOpenKey(
        &(_this->ProductOptionsKey),
        KEY_READ,
        &KeyAttribute
    );
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }


    ULONG ResultLength = 0;
    KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    Status = ZwQueryValueKey(
        _this->ProductOptionsKey,
        &gProductPolicyValueName,
        KeyValuePartialInformation,
        &KeyInfo,
        sizeof(KeyInfo),
        &ResultLength
    );
    if (Status != STATUS_BUFFER_OVERFLOW && 
        Status != STATUS_BUFFER_TOO_SMALL && 
        Status != STATUS_SUCCESS)
    {
        goto finalize;
    }
    _this->ProductPolicyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        ResultLength, 
        uTag
    );
    if (_this->ProductPolicyValueInfo == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto finalize;
    }
    _this->ProductPolicyValueInfoSize = ResultLength;


    _this->pFunc = Worker_Work;


    InitializeObjectAttributes(
        &ThreadAttribute,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );
    Status = PsCreateSystemThread(
        &(_this->WorkerHandle),
        THREAD_ALL_ACCESS,
        &ThreadAttribute,
        NULL,
        NULL,
        _this->pFunc,
        __this
    );
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }



    Status = ObReferenceObjectByHandle(
        _this->WorkerHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        &(_this->WorkerObject),
        NULL
    );
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }


    Status = STATUS_SUCCESS;

finalize:
    if (!NT_SUCCESS(Status))
    {
        if (_this) {
            Worker_Delete(__this);
        }
    }
    return Status;
}
#pragma code_seg ()

#pragma code_seg ("INIT")
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;

    for (int n = 0; n <= IRP_MJ_MAXIMUM_FUNCTION; n++) {
        DriverObject->MajorFunction[n] = OnOther;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;

    DriverObject->DriverUnload = OnUnload;

    Status = Worker_MakeAndInitialize(&Worker);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }

    return CreateApiDevice(DriverObject);

finalize:
    return Status;
}
#pragma code_seg ()

#pragma code_seg ("PAGE")
VOID OnUnload(PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();      // keep the static analysis tools happy 

    if (Worker)
    {
        PVOID WorkerObject = Worker->WorkerObject;
        HANDLE WorkerHandle = Worker->WorkerHandle;
        KeSetEvent(
            Worker->UnloadEventObject,
            IO_NO_INCREMENT,
            TRUE
        );
        KeWaitForSingleObject(
            WorkerObject,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
        ObDereferenceObject(WorkerObject);
        ZwClose(WorkerHandle);
    }

    DestroyApiDevice(DriverObject);
}
#pragma code_seg ()

#pragma code_seg ()
FORCEINLINE
NTSTATUS IrpDispatchDone(
    PIRP Irp, 
    NTSTATUS Status
)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
#pragma code_seg ()

#pragma code_seg ()
FORCEINLINE
NTSTATUS IrpDispatchDoneEx(
    PIRP Irp,
    NTSTATUS Status,
    ULONG Information
)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}
#pragma code_seg ()

#pragma code_seg ("PAGE")
NTSTATUS OnCreate(
    PDEVICE_OBJECT DeviceObject, 
    PIRP Irp
)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT fileobj = sl->FileObject;
    PUNICODE_STRING filename = &(fileobj->FileName);
    NTSTATUS status = filename->Length != 0
        ? STATUS_INVALID_PARAMETER
        : STATUS_SUCCESS;

    return IrpDispatchDone(Irp, status);
}
#pragma code_seg ()

#pragma code_seg ("PAGE")
NTSTATUS OnClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    return IrpDispatchDone(Irp, STATUS_SUCCESS);
}
#pragma code_seg ()

#pragma code_seg ()
NTSTATUS OnDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    ULONG numret = 0;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(Irp);
    ULONG inlen = sl->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outlen = sl->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status;

    switch (sl->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_SELFSIGN_GET_VERSION: {
        status = OnApiGetInfo(buf, inlen, outlen, &numret);
        break;
    }
    default: {
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    }
    return IrpDispatchDoneEx(Irp, status, numret);
}
#pragma code_seg ()

#pragma code_seg ()
NTSTATUS OnOther(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    return IrpDispatchDone(Irp, STATUS_INVALID_DEVICE_REQUEST);
}
#pragma code_seg ()

/*  ************************************************************************  */
/*  API Support  */

#define API_DEVICE_NAME     L"\\Device\\"   SSDE_DEVICE_NAME
#define API_LINK_NAME       L"\\??\\"       SSDE_DEVICE_NAME

PDEVICE_OBJECT ApiDevice = NULL;

#pragma code_seg ("INIT")
NTSTATUS CreateApiDevice(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING devname;
    RtlInitUnicodeString(&devname, API_DEVICE_NAME);

    PDEVICE_OBJECT devobj;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devname,
        FILE_DEVICE_UNKNOWN,
        0,
        TRUE,
        &devobj);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING linkname;

        RtlInitUnicodeString(&linkname, API_LINK_NAME);

        status = IoCreateSymbolicLink(&linkname, &devname);
        if (NT_SUCCESS(status)) {
            ApiDevice = devobj;
            return STATUS_SUCCESS;
        }

        IoDeleteDevice(devobj);
    }
    return status;
}
#pragma code_seg ()

#pragma code_seg ("PAGE")
VOID DestroyApiDevice(PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);

    if (ApiDevice == NULL) return;

    UNICODE_STRING linkname;
    RtlInitUnicodeString(&linkname, API_LINK_NAME);
    IoDeleteSymbolicLink(&linkname);

    IoDeleteDevice(ApiDevice);
}
#pragma code_seg ()

#pragma code_seg ("PAGE")
NTSTATUS
OnApiGetInfo(
    PVOID Buffer,
    ULONG InLen,
    ULONG OutLen,
    ULONG* NumRet)
{
    PAGED_CODE();

    SSDE_API_INFO* pver;

    if (InLen != 0 || OutLen != sizeof(*pver) || Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    pver = (SSDE_API_INFO*)Buffer;
    pver->Minor = SSDE_API_MINOR_VERSION;
    pver->Major = SSDE_API_MAJOR_VERSION;
    pver->ArmCount = ArmCount;
    pver->Status = ArmWatchdog;
    ExGetLicenseTamperState(&(pver->TamperState));

    *NumRet = sizeof(*pver);
    return STATUS_SUCCESS;
}
#pragma code_seg ()