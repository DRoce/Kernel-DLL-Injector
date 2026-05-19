#pragma once

//
// AegisDriver2 — Shared Memory Communication Protocol
// This header is shared between the kernel driver and usermode client.
//

// Protocol identity. Bump this and the object names together when struct layouts change.
#define AEGIS2_PROTOCOL_MAGIC   0x32475341u  // 'ASG2'
#define AEGIS2_PROTOCOL_VERSION 3u

// Named objects for shared memory and synchronization
#define AEGIS2_SECTION_NAME     L"\\BaseNamedObjects\\Aegis2V3SharedSection"
#define AEGIS2_REQUEST_EVENT    L"\\BaseNamedObjects\\Aegis2V3RequestEvent"
#define AEGIS2_COMPLETION_EVENT L"\\BaseNamedObjects\\Aegis2V3CompletionEvent"

// Usermode names (no \BaseNamedObjects prefix)
#define AEGIS2_UM_SECTION_NAME     L"Global\\Aegis2V3SharedSection"
#define AEGIS2_UM_REQUEST_EVENT    L"Global\\Aegis2V3RequestEvent"
#define AEGIS2_UM_COMPLETION_EVENT L"Global\\Aegis2V3CompletionEvent"
#define AEGIS2_UM_COMMAND_MUTEX    L"Global\\Aegis2V3CommandMutex"

// Shared memory size
#define AEGIS2_SHARED_SIZE  0x10000  // 64KB

// User-mode wait timeout for one driver command.
#define AEGIS2_COMMAND_TIMEOUT_MS 10000u

// Command IDs
enum AEGIS2_COMMAND : unsigned int
{
    CMD_NONE = 0,
    CMD_READ_MEMORY = 1,
    CMD_WRITE_MEMORY = 2,
    CMD_ALLOC_MEMORY = 3,
    CMD_FREE_MEMORY = 4,
    CMD_CREATE_THREAD = 5,
    CMD_PING = 0xFF,
};

// Status codes
enum AEGIS2_STATUS : unsigned int
{
    STATUS_AEGIS_SUCCESS = 0,
    STATUS_AEGIS_FAILED = 1,
    STATUS_AEGIS_INVALID_CMD = 2,
    STATUS_AEGIS_PROCESS_NOT_FOUND = 3,
    STATUS_AEGIS_INVALID_PARAMETER = 4,
    STATUS_AEGIS_PARTIAL_COPY = 5,
};

// Request header (always at offset 0 of shared memory)
struct AEGIS2_HEADER
{
    unsigned int          magic;        // AEGIS2_PROTOCOL_MAGIC
    unsigned int          version;      // AEGIS2_PROTOCOL_VERSION
    volatile unsigned int command;      // AEGIS2_COMMAND
    volatile unsigned int status;       // AEGIS2_STATUS (set by driver)
    unsigned int          target_pid;   // Target process ID
    int                   ntstatus;     // Raw NTSTATUS for diagnostics
};

// CMD_READ_MEMORY / CMD_WRITE_MEMORY
struct AEGIS2_COPY_MEMORY
{
    AEGIS2_HEADER header;
    unsigned long long address;         // Target address
    unsigned int       size;            // Number of bytes
    unsigned char      data[0xFF00];    // Data buffer (read into / write from)
};

// CMD_ALLOC_MEMORY
struct AEGIS2_ALLOC_MEMORY
{
    AEGIS2_HEADER header;
    unsigned long long out_address;     // Result: allocated address
    unsigned int       size;            // Requested size
    unsigned int       protect;         // PAGE_* protection
};

// CMD_FREE_MEMORY
struct AEGIS2_FREE_MEMORY
{
    AEGIS2_HEADER header;
    unsigned long long address;         // Address to free
};

// CMD_CREATE_THREAD
struct AEGIS2_CREATE_THREAD
{
    AEGIS2_HEADER header;
    unsigned long long start_address;   // Thread start routine (e.g. LoadLibraryA)
    unsigned long long parameter;       // Parameter to pass (e.g. DLL path pointer)
    unsigned int       wait_ms;         // How long to wait for completion (0 = don't wait)
    unsigned long long thread_exit_code;// Result: thread exit code
};
