#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include "../driver/shared_defs.h"

// Undocumented structures and functions required for APC thread injection
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2);

typedef VOID KKERNEL_ROUTINE(
    _In_ PRKAPC Apc,
    _Inout_opt_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_opt_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);
typedef KKERNEL_ROUTINE(NTAPI* PKKERNEL_ROUTINE);
typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(_In_ PRKAPC Apc);

extern "C" {
    VOID NTAPI KeInitializeApc(
        _Out_ PRKAPC Apc,
        _In_ PRKTHREAD Thread,
        _In_ KAPC_ENVIRONMENT Environment,
        _In_ PKKERNEL_ROUTINE KernelRoutine,
        _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
        _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
        _In_opt_ KPROCESSOR_MODE ProcessorMode,
        _In_opt_ PVOID NormalContext
    );

    BOOLEAN NTAPI KeInsertQueueApc(
        _Inout_ PRKAPC Apc,
        _In_opt_ PVOID SystemArgument1,
        _In_opt_ PVOID SystemArgument2,
        _In_ KPRIORITY Increment
    );

    NTSTATUS NTAPI MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );
    
    NTSTATUS ZwQuerySystemInformation(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );
}

// Global state
HANDLE g_SectionHandle = NULL;
PVOID  g_SectionObject = NULL;
PVOID  g_SharedMemory = NULL;
PKEVENT g_RequestEvent = NULL;
PKEVENT g_CompletionEvent = NULL;
HANDLE  g_ReqEventHandle = NULL;
HANDLE  g_CompEventHandle = NULL;
PVOID   g_WorkerThreadObject = NULL;
volatile LONG g_DriverUnloading = 0;

static const ULONG AEGIS2_POOL_TAG = '2geA';
static const ULONG AEGIS2_COPY_DATA_SIZE = sizeof(((AEGIS2_COPY_MEMORY*)0)->data);

static NTSTATUS InitializeOpenSecurityDescriptor(SECURITY_DESCRIPTOR* securityDescriptor)
{
    NTSTATUS status = RtlCreateSecurityDescriptor(securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status))
        return status;

    return RtlSetDaclSecurityDescriptor(securityDescriptor, TRUE, NULL, FALSE);
}

static BOOLEAN IsDriverUnloading()
{
    return InterlockedCompareExchange(&g_DriverUnloading, 0, 0) != 0;
}

static BOOLEAN IsValidCopyRequest(const AEGIS2_COPY_MEMORY* cmd)
{
    if (!cmd || cmd->header.target_pid == 0 || cmd->address == 0)
        return FALSE;

    if (cmd->size == 0 || cmd->size > AEGIS2_COPY_DATA_SIZE)
        return FALSE;

    return TRUE;
}

static unsigned int CopyStatusFromNtStatus(NTSTATUS status, SIZE_T requestedSize, SIZE_T bytesCopied)
{
    if (!NT_SUCCESS(status))
        return STATUS_AEGIS_FAILED;

    return bytesCopied == requestedSize ? STATUS_AEGIS_SUCCESS : STATUS_AEGIS_PARTIAL_COPY;
}

static NTSTATUS SafeMmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize)
{
    __try
    {
        return MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (ReturnSize)
            *ReturnSize = 0;
        return GetExceptionCode();
    }
}

static unsigned int HandleReadMemory(AEGIS2_COPY_MEMORY* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!IsValidCopyRequest(cmd))
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    const HANDLE targetPid = (HANDLE)(ULONG_PTR)cmd->header.target_pid;
    const PVOID targetAddress = (PVOID)(ULONG_PTR)cmd->address;
    const SIZE_T requestedSize = cmd->size;

    PVOID scratch = ExAllocatePool2(POOL_FLAG_NON_PAGED, requestedSize, AEGIS2_POOL_TAG);
    if (!scratch)
    {
        if (outNtStatus) *outNtStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_AEGIS_FAILED;
    }

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(targetPid, &process);
    if (!NT_SUCCESS(status))
    {
        if (outNtStatus) *outNtStatus = status;
        ExFreePoolWithTag(scratch, AEGIS2_POOL_TAG);
        return STATUS_AEGIS_PROCESS_NOT_FOUND;
    }

    SIZE_T bytesCopied = 0;
    status = SafeMmCopyVirtualMemory(process, targetAddress, PsGetCurrentProcess(), scratch, requestedSize, KernelMode, &bytesCopied);

    if (NT_SUCCESS(status) && bytesCopied == requestedSize)
        RtlCopyMemory(cmd->data, scratch, requestedSize);

    ObDereferenceObject(process);
    ExFreePoolWithTag(scratch, AEGIS2_POOL_TAG);
    if (outNtStatus) *outNtStatus = status;
    return CopyStatusFromNtStatus(status, requestedSize, bytesCopied);
}

static unsigned int HandleWriteMemory(AEGIS2_COPY_MEMORY* cmd, NTSTATUS* outNtStatus)
{
    if (outNtStatus) *outNtStatus = STATUS_SUCCESS;

    if (!IsValidCopyRequest(cmd))
    {
        if (outNtStatus) *outNtStatus = STATUS_INVALID_PARAMETER;
        return STATUS_AEGIS_INVALID_PARAMETER;
    }

    const HANDLE targetPid = (HANDLE)(ULONG_PTR)cmd->header.target_pid;
    const PVOID targetAddress = (PVOID)(ULONG_PTR)cmd->address;
    const SIZE_T requestedSize = cmd->size;

    PVOID scratch = ExAllocatePool2(POOL_FLAG_NON_PAGED, requestedSize, AEGIS2_POOL_TAG);
    if (!scratch)
    {
        if (outNtStatus) *outNtStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_AEGIS_FAILED;
    }

    RtlCopyMemory(scratch, cmd->data, requestedSize);

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(targetPid, &process);
    if (!NT_SUCCESS(status))
    {
        if (outNtStatus) *outNtStatus = status;
        ExFreePoolWithTag(scratch, AEGIS2_POOL_TAG);
        return STATUS_AEGIS_PROCESS_NOT_FOUND;
    }

    SIZE_T bytesCopied = 0;
    status = SafeMmCopyVirtualMemory(PsGetCurrentProcess(), scratch, process, targetAddress, requestedSize, KernelMode, &bytesCopied);

    ObDereferenceObject(process);
    ExFreePoolWithTag(scratch, AEGIS2_POOL_TAG);
    if (outNtStatus) *outNtStatus = status;
    return CopyStatusFromNtStatus(status, requestedSize, bytesCopied);
}

// APC execution kernel routine
VOID ApcKernelRoutine(
    _In_ PRKAPC Apc,
    _Inout_opt_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_opt_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePoolWithTag(Apc, 'CpaA');
}

// CMD_CREATE_THREAD is intentionally not implemented in this shared-memory backend.
// Returning success here would make user mode report a thread creation that never happened.
NTSTATUS HandleCreateThread(AEGIS2_CREATE_THREAD* cmd)
{
    UNREFERENCED_PARAMETER(cmd);
    return STATUS_AEGIS_FAILED;
}

// Worker thread that polls the shared memory
VOID WorkerThread(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    while (!IsDriverUnloading())
    {
        // Wait for a request
        NTSTATUS status = KeWaitForSingleObject(g_RequestEvent, Executive, KernelMode, FALSE, NULL);
        if (IsDriverUnloading()) break;
        if (status != STATUS_WAIT_0) continue;

        if (!g_SharedMemory)
        {
            KeSetEvent(g_CompletionEvent, 0, FALSE);
            continue;
        }

        AEGIS2_HEADER* header = (AEGIS2_HEADER*)g_SharedMemory;
        header->ntstatus = STATUS_SUCCESS;

        if (header->magic != AEGIS2_PROTOCOL_MAGIC || header->version != AEGIS2_PROTOCOL_VERSION)
        {
            header->status = STATUS_AEGIS_INVALID_PARAMETER;
            header->ntstatus = STATUS_INVALID_PARAMETER;
            header->command = CMD_NONE;
            KeClearEvent(g_RequestEvent);
            KeSetEvent(g_CompletionEvent, 0, FALSE);
            continue;
        }
        
        if (header->command == CMD_PING)
        {
            header->status = STATUS_AEGIS_SUCCESS;
            header->ntstatus = STATUS_SUCCESS;
        }
        else if (header->command == CMD_READ_MEMORY)
        {
            AEGIS2_COPY_MEMORY* cmd = (AEGIS2_COPY_MEMORY*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleReadMemory(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_WRITE_MEMORY)
        {
            AEGIS2_COPY_MEMORY* cmd = (AEGIS2_COPY_MEMORY*)g_SharedMemory;
            NTSTATUS commandStatus = STATUS_SUCCESS;
            header->status = HandleWriteMemory(cmd, &commandStatus);
            header->ntstatus = commandStatus;
        }
        else if (header->command == CMD_ALLOC_MEMORY)
        {
            AEGIS2_ALLOC_MEMORY* cmd = (AEGIS2_ALLOC_MEMORY*)g_SharedMemory;
            if (cmd->size == 0 || header->target_pid == 0)
            {
                header->status = STATUS_AEGIS_INVALID_PARAMETER;
                header->ntstatus = STATUS_INVALID_PARAMETER;
            }
            else
            {
                PEPROCESS Process = NULL;
                NTSTATUS lookupStatus = PsLookupProcessByProcessId((HANDLE)header->target_pid, &Process);
                if (NT_SUCCESS(lookupStatus))
                {
                    SIZE_T RegionSize = cmd->size;
                    ULONG Protect = cmd->protect;
                    PVOID BaseAddress = NULL;

                    HANDLE hProcess = NULL;
                    CLIENT_ID clientId;
                    clientId.UniqueProcess = (HANDLE)header->target_pid;
                    clientId.UniqueThread = NULL;
                    OBJECT_ATTRIBUTES objAttr;
                    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                
                    NTSTATUS allocStatus = STATUS_UNSUCCESSFUL;
                    NTSTATUS openStatus = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
                    if (NT_SUCCESS(openStatus))
                    {
                        allocStatus = ZwAllocateVirtualMemory(hProcess, &BaseAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, Protect);
                        ZwClose(hProcess);
                    }
                    else
                    {
                        allocStatus = openStatus;
                    }
                
                    if (NT_SUCCESS(allocStatus))
                    {
                        cmd->out_address = (ULONGLONG)BaseAddress;
                        header->status = STATUS_AEGIS_SUCCESS;
                        header->ntstatus = STATUS_SUCCESS;
                    }
                    else
                    {
                        header->status = STATUS_AEGIS_FAILED;
                        header->ntstatus = allocStatus;
                    }
                
                    ObDereferenceObject(Process);
                }
                else
                {
                    header->status = STATUS_AEGIS_PROCESS_NOT_FOUND;
                    header->ntstatus = lookupStatus;
                }
            }
        }
        else if (header->command == CMD_FREE_MEMORY)
        {
            AEGIS2_FREE_MEMORY* cmd = (AEGIS2_FREE_MEMORY*)g_SharedMemory;
            if (cmd->address == 0 || header->target_pid == 0)
            {
                header->status = STATUS_AEGIS_INVALID_PARAMETER;
                header->ntstatus = STATUS_INVALID_PARAMETER;
            }
            else
            {
                PEPROCESS Process = NULL;
                NTSTATUS lookupStatus = PsLookupProcessByProcessId((HANDLE)header->target_pid, &Process);
                if (NT_SUCCESS(lookupStatus))
                {
                    PVOID BaseAddress = (PVOID)cmd->address;
                    SIZE_T RegionSize = 0; // Must be 0 for MEM_RELEASE

                    HANDLE hProcess = NULL;
                    CLIENT_ID clientId;
                    clientId.UniqueProcess = (HANDLE)header->target_pid;
                    clientId.UniqueThread = NULL;
                    OBJECT_ATTRIBUTES objAttr;
                    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                
                    NTSTATUS freeStatus = STATUS_UNSUCCESSFUL;
                    NTSTATUS openStatus = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
                    if (NT_SUCCESS(openStatus))
                    {
                        freeStatus = ZwFreeVirtualMemory(hProcess, &BaseAddress, &RegionSize, MEM_RELEASE);
                        ZwClose(hProcess);
                    }
                    else
                    {
                        freeStatus = openStatus;
                    }
                
                    if (NT_SUCCESS(freeStatus))
                    {
                        header->status = STATUS_AEGIS_SUCCESS;
                        header->ntstatus = STATUS_SUCCESS;
                    }
                    else
                    {
                        header->status = STATUS_AEGIS_FAILED;
                        header->ntstatus = freeStatus;
                    }
                
                    ObDereferenceObject(Process);
                }
                else
                {
                    header->status = STATUS_AEGIS_PROCESS_NOT_FOUND;
                    header->ntstatus = lookupStatus;
                }
            }
        }
        else if (header->command == CMD_CREATE_THREAD)
        {
            AEGIS2_CREATE_THREAD* cmd = (AEGIS2_CREATE_THREAD*)g_SharedMemory;
            header->status = HandleCreateThread(cmd);
            header->ntstatus = STATUS_NOT_IMPLEMENTED;
        }
        else
        {
            header->status = STATUS_AEGIS_INVALID_CMD;
            header->ntstatus = STATUS_INVALID_DEVICE_REQUEST;
        }

        // Reset command and signal completion
        header->command = CMD_NONE;
        KeClearEvent(g_RequestEvent);
        KeSetEvent(g_CompletionEvent, 0, FALSE);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// Cleanup resources
VOID CleanupResources()
{
    InterlockedExchange(&g_DriverUnloading, 1);

    if (g_RequestEvent) KeSetEvent(g_RequestEvent, 0, FALSE); // Wake thread

    if (g_WorkerThreadObject)
    {
        KeWaitForSingleObject(g_WorkerThreadObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_WorkerThreadObject);
        g_WorkerThreadObject = NULL;
    }

    if (g_SharedMemory)
    {
        MmUnmapViewInSystemSpace(g_SharedMemory);
        g_SharedMemory = NULL;
    }

    if (g_SectionObject)
    {
        ObDereferenceObject(g_SectionObject);
        g_SectionObject = NULL;
    }

    if (g_ReqEventHandle)
    {
        if (g_RequestEvent)
        {
            ObDereferenceObject(g_RequestEvent);
            g_RequestEvent = NULL;
        }

        ZwClose(g_ReqEventHandle);
        g_ReqEventHandle = NULL;
    }

    if (g_CompEventHandle)
    {
        if (g_CompletionEvent)
        {
            ObDereferenceObject(g_CompletionEvent);
            g_CompletionEvent = NULL;
        }

        ZwClose(g_CompEventHandle);
        g_CompEventHandle = NULL;
    }

    if (g_SectionHandle)
    {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
    }
}

extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    CleanupResources();
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    if (DriverObject)
        DriverObject->DriverUnload = DriverUnload;

    InterlockedExchange(&g_DriverUnloading, 0);

    NTSTATUS status;
    UNICODE_STRING sectionName, reqEventName, compEventName;
    OBJECT_ATTRIBUTES objAttrSection, objAttrReq, objAttrComp;
    LARGE_INTEGER sectionSize;
    SECURITY_DESCRIPTOR securityDescriptor;

    status = InitializeOpenSecurityDescriptor(&securityDescriptor);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&sectionName, AEGIS2_SECTION_NAME);
    RtlInitUnicodeString(&reqEventName, AEGIS2_REQUEST_EVENT);
    RtlInitUnicodeString(&compEventName, AEGIS2_COMPLETION_EVENT);

    InitializeObjectAttributes(&objAttrSection, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);
    InitializeObjectAttributes(&objAttrReq, &reqEventName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);
    InitializeObjectAttributes(&objAttrComp, &compEventName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &securityDescriptor);

    // Create shared memory section
    sectionSize.QuadPart = AEGIS2_SHARED_SIZE;
    status = ZwCreateSection(&g_SectionHandle, SECTION_ALL_ACCESS, &objAttrSection, &sectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) return status;

    PVOID viewBase = NULL;
    SIZE_T viewSize = AEGIS2_SHARED_SIZE;
    status = ObReferenceObjectByHandle(g_SectionHandle, SECTION_ALL_ACCESS, NULL, KernelMode, &g_SectionObject, NULL);
    if (!NT_SUCCESS(status))
    {
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return status;
    }

    status = MmMapViewInSystemSpace(g_SectionObject, &viewBase, &viewSize);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(g_SectionObject);
        g_SectionObject = NULL;
        ZwClose(g_SectionHandle);
        g_SectionHandle = NULL;
        return status;
    }

    g_SharedMemory = viewBase;
    RtlZeroMemory(g_SharedMemory, AEGIS2_SHARED_SIZE);

    // Create events (named events for usermode communication)
    status = ZwCreateEvent(&g_ReqEventHandle, EVENT_ALL_ACCESS, &objAttrReq, NotificationEvent, FALSE);
    if (!NT_SUCCESS(status))
    {
        CleanupResources();
        return status;
    }

    status = ObReferenceObjectByHandle(g_ReqEventHandle, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID*)&g_RequestEvent, NULL);
    if (!NT_SUCCESS(status))
    {
        CleanupResources();
        return status;
    }

    status = ZwCreateEvent(&g_CompEventHandle, EVENT_ALL_ACCESS, &objAttrComp, NotificationEvent, FALSE);
    if (!NT_SUCCESS(status))
    {
        CleanupResources();
        return status;
    }

    status = ObReferenceObjectByHandle(g_CompEventHandle, EVENT_ALL_ACCESS, NULL, KernelMode, (PVOID*)&g_CompletionEvent, NULL);
    if (!NT_SUCCESS(status))
    {
        CleanupResources();
        return status;
    }

    if (!g_RequestEvent || !g_CompletionEvent)
    {
        CleanupResources();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeClearEvent(g_RequestEvent);
    KeClearEvent(g_CompletionEvent);

    // Start worker thread
    HANDLE threadHandle;
    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkerThread, NULL);
    if (NT_SUCCESS(status))
    {
        status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &g_WorkerThreadObject, NULL);
        if (!NT_SUCCESS(status))
        {
            InterlockedExchange(&g_DriverUnloading, 1);
            KeSetEvent(g_RequestEvent, 0, FALSE);
            ZwWaitForSingleObject(threadHandle, FALSE, NULL);
            ZwClose(threadHandle);
            CleanupResources();
            return status;
        }
        ZwClose(threadHandle);
    }
    else
    {
        CleanupResources();
        return status;
    }

    return STATUS_SUCCESS;
}
