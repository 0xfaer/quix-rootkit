#include <ntddk.h>
#include <ntifs.h>
#define DEVICE_RK 0x00008001
#define MSR_EIP 0x176
#define nCPUs 32
#define PRNTFREQ 1000

typedef struct _MSR
{
	DWORD32 loaddr;
	DWORD32 highaddr;
}
MSR, *PMSR;

DWORD32 originalMSRlovalue = 0;
DWORD32 currentindex = 0;

const WCHAR *devicepath = L "\\Device\\HookRK";
const WCHAR *linkdevicepath = L "\\DosDevices\\HookRK";
PDEVICE_OBJECT devobj;

NTSTATUS default_dispatch(PDRIVER_OBJECT pobj, PIRP pirp)
{
	UNREFERENCED_PARAMETER(pobj);
	DbgPrint("Entering default_dispatch Method \n");
	pirp->IoStatus.Status = STATUS_SUCCESS;
	pirp->IoStatus.Information = 0;
	IoCompleteRequest(pirp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS RegisterDriverDeviceName(PDRIVER_OBJECT pobj)
{
	NTSTATUS ntstatus;
	UNICODE_STRING unistring;

	RtlInitUnicodeString(&unistring, devicepath);

	ntstatus = IoCreateDevice(		pobj,
		0, &unistring,
		DEVICE_RK,
		0,
		TRUE, &devobj
);
	return ntstatus;
}

NTSTATUS RegisterDriverDeviceLink(void)
{
	NTSTATUS ntstatus;

	UNICODE_STRING deviceunistring;
	UNICODE_STRING devicelinkunistring;

	RtlInitUnicodeString(&deviceunistring, devicepath);
	RtlInitUnicodeString(&devicelinkunistring, linkdevicepath);

	ntstatus = IoCreateSymbolicLink(&devicelinkunistring, &deviceunistring);

	return ntstatus;
}

void prnthookmsg(DWORD32 dispatchid, DWORD32 stackPtr)
{
	if (currentindex == PRNTFREQ)
	{
		DbgPrint("[PRNTHOOKMSG]: on CPU[%u], (pid=%u, dispatchID=%x), Addr of stack = 0x%x \n",
			KeGetCurrentProcessorNumber(), PsGetCurrentProcessId(), dispatchid, &stackPtr);

		currentindex = 0;
	}
	currentindex++;
}

void __declspec(naked) newMSR(void)
{
	__asm
	{
		pushad;
		pushfd;

		mov ecx, 0x23;
		push 0x30;
		pop fs;
		mov ds, cx;
		mov es, cx;
		nop
		push edx;
		push eax;
		call prnthookmsg;
		popfd;
		popad;
		jmp[originalMSRlovalue];
	}
}

void readMSR(DWORD32 regnumber, PMSR msr)
{
	DWORD32 loval;
	DWORD32 hival;

	__asm
	{
		mov ecx, regnumber;
		rdmsr;
		mov hival, edx;
		mov loval, eax;
	}

	msr->highaddr = hival;
	msr->loaddr = loval;

	return;
}

void setMSR(DWORD32 regnumber, PMSR msr)
{
	DWORD32 loval;
	DWORD32 hival;

	hival = msr->highaddr;
	loval = msr->loaddr;

	__asm
	{
		mov ecx, regnumber;
		mov edx, hival;
		mov eax, loval;
		wrmsr;
	}
	return;
}

DWORD32 HookCPU(DWORD32 procaddr)
{
	PMSR oldmsr = NULL;
	PMSR newmsr = NULL;

	readMSR(MSR_EIP, oldmsr);

	newmsr->loaddr = oldmsr->loaddr;
	newmsr->highaddr = newmsr->highaddr;

	newmsr->loaddr = procaddr;

	setMSR(MSR_EIP, newmsr);

	return oldmsr->loaddr;
}

void HookAllCPUs(DWORD32 procaddr)
{
	KAFFINITY threadaffinity;
	KAFFINITY currentCPU;

	threadaffinity = KeQueryActiveProcessors();

	for (DWORD32 i = 0; i < nCPUs; i++)
	{
		currentCPU = threadaffinity &(1 << i);

		if (currentCPU != 0)
		{
			KeSetSystemAffinityThread(threadaffinity);

			if (originalMSRlovalue == 0)
			{
				originalMSRlovalue = HookCPU(procaddr);
			}
			else
			{
				HookCPU(procaddr);
			}
		}
	}

	KeSetSystemAffinityThread(threadaffinity);

	PsTerminateSystemThread(STATUS_SUCCESS);
	return;
}

void HookSysEnter(DWORD32 ProcessAddr)
{
	HANDLE hthread;
	OBJECT_ATTRIBUTES objattributes;
	LARGE_INTEGER timer;

	InitializeObjectAttributes(&objattributes, NULL, 0, NULL, NULL);

	PsCreateSystemThread(&hthread, THREAD_ALL_ACCESS, &objattributes, NULL, NULL, (PKSTART_ROUTINE) HookAllCPUs, (PVOID) ProcessAddr);

	ObReferenceObjectByHandle(hthread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*) pkthreadobj, NULL);

	timer.QuadPart = 300;
	while (KeWaitForSingleObject((PVOID) pkthreadobj, Executive, KernelMode, FALSE, &timer) != STATUS_SUCCESS) {}

	ZwClose(hthread);
	return;
}

void unload(PDRIVER_OBJECT pobj)
{
	DbgPrint("Unloading the Device\n");
	PDEVICE_OBJECT pdevobj;
	UNICODE_STRING unistring;

	pdevobj = pobj->DeviceObject;

	RtlInitUnicodeString(&unistring, linkdevicepath);
	IoDeleteSymbolicLink(&unistring);

	RtlInitUnicodeString(&unistring, linkdevicepath);
	IoDeleteDevice(pdevobj);

	return;
}

extern "C"
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING regpath)
{
	UNREFERENCED_PARAMETER(regpath);
	DbgPrint("Entering The Device Driver Main Fcn\n");
	int i;
	NTSTATUS ntstatus;

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = (PDRIVER_DISPATCH) default_dispatch;
	}

	pDriverObject->DriverUnload = unload;

	ntstatus = RegisterDriverDeviceName(pDriverObject);

	if (!NT_SUCCESS(ntstatus))
	{
		return ntstatus;
	}

	ntstatus = RegisterDriverDeviceLink();
	if (!NT_SUCCESS(ntstatus))
	{
		return ntstatus;
	}

	HookSysEnter((DWORD32) prnthookmsg);

	return STATUS_SUCCESS;
}
