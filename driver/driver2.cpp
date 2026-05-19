#include "driver2.h"
#include <iostream>
#include <iomanip>

static const char* aegis2_status_name(unsigned int status)
{
    switch (status)
    {
    case STATUS_AEGIS_SUCCESS: return "SUCCESS";
    case STATUS_AEGIS_FAILED: return "FAILED";
    case STATUS_AEGIS_INVALID_CMD: return "INVALID_CMD";
    case STATUS_AEGIS_PROCESS_NOT_FOUND: return "PROCESS_NOT_FOUND";
    case STATUS_AEGIS_INVALID_PARAMETER: return "INVALID_PARAMETER";
    case STATUS_AEGIS_PARTIAL_COPY: return "PARTIAL_COPY";
    default: return "UNKNOWN";
    }
}

static void log_aegis2_failure(const char* operation, const AEGIS2_HEADER& header)
{
    std::cout << "[-] Driver " << operation << " failed. status=" << header.status
              << " (" << aegis2_status_name(header.status) << ") ntstatus=0x"
              << std::hex << std::uppercase << (unsigned int)header.ntstatus
              << std::nouppercase << std::dec << std::endl;
}

static void prepare_aegis2_header(AEGIS2_HEADER& header, unsigned int command, DWORD target_pid = 0)
{
    header.magic = AEGIS2_PROTOCOL_MAGIC;
    header.version = AEGIS2_PROTOCOL_VERSION;
    header.command = command;
    header.status = STATUS_AEGIS_FAILED;
    header.target_pid = target_pid;
    header.ntstatus = 0;
}

c_driver2::c_driver2()
    : m_section(nullptr), m_request_event(nullptr),
      m_completion_event(nullptr), m_command_mutex(nullptr),
      m_shared(nullptr), m_pid(0)
{
}

c_driver2::~c_driver2()
{
    disconnect();
}

c_driver2& c_driver2::singleton()
{
    static c_driver2 instance;
    return instance;
}

bool c_driver2::connect()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_shared && m_section && m_request_event && m_completion_event && m_command_mutex)
    {
        std::cout << "[+] AegisDriver2 shared memory is already connected. protocol=v"
                  << AEGIS2_PROTOCOL_VERSION << std::endl;
        return true;
    }

    disconnect_unlocked();

    // Open the shared memory section created by the driver
    m_section = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, AEGIS2_UM_SECTION_NAME);
    if (!m_section)
    {
        std::cout << "[-] Failed to open shared section. Is AegisDriver2 loaded? GetLastError="
                  << GetLastError() << std::endl;
        return false;
    }

    m_shared = MapViewOfFile(m_section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, AEGIS2_SHARED_SIZE);
    if (!m_shared)
    {
        std::cout << "[-] Failed to map shared memory view. GetLastError="
                  << GetLastError() << std::endl;
        disconnect_unlocked();
        return false;
    }

    // Open synchronization events
    m_request_event = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, AEGIS2_UM_REQUEST_EVENT);
    DWORD request_error = m_request_event ? ERROR_SUCCESS : GetLastError();
    m_completion_event = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, AEGIS2_UM_COMPLETION_EVENT);
    DWORD completion_error = m_completion_event ? ERROR_SUCCESS : GetLastError();
    m_command_mutex = CreateMutexW(nullptr, FALSE, AEGIS2_UM_COMMAND_MUTEX);
    DWORD mutex_error = m_command_mutex ? ERROR_SUCCESS : GetLastError();

    if (!m_request_event || !m_completion_event || !m_command_mutex)
    {
        std::cout << "[-] Failed to open sync events. request_error=" << request_error
                  << " completion_error=" << completion_error
                  << " mutex_error=" << mutex_error << std::endl;
        disconnect_unlocked();
        return false;
    }

    std::cout << "[+] Connected to AegisDriver2 via shared memory. protocol=v"
              << AEGIS2_PROTOCOL_VERSION << std::endl;
    return true;
}

void c_driver2::disconnect_unlocked()
{
    if (m_shared) { UnmapViewOfFile(m_shared); m_shared = nullptr; }
    if (m_section) { CloseHandle(m_section); m_section = nullptr; }
    if (m_request_event) { CloseHandle(m_request_event); m_request_event = nullptr; }
    if (m_completion_event) { CloseHandle(m_completion_event); m_completion_event = nullptr; }
    if (m_command_mutex) { CloseHandle(m_command_mutex); m_command_mutex = nullptr; }
    m_pid = 0;
}

void c_driver2::disconnect()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    disconnect_unlocked();
}

void c_driver2::attach_process(DWORD pid)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pid = pid;
}

bool c_driver2::is_connected() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_shared && m_section && m_request_event && m_completion_event && m_command_mutex;
}

DWORD c_driver2::get_pid() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pid;
}

c_driver2::command_lock::command_lock(c_driver2& owner)
    : m_owner(owner), m_locked(owner.acquire_command_mutex())
{
}

c_driver2::command_lock::~command_lock()
{
    if (m_locked)
        m_owner.release_command_mutex();
}

bool c_driver2::command_lock::locked() const
{
    return m_locked;
}

bool c_driver2::acquire_command_mutex()
{
    if (!m_command_mutex)
    {
        std::cout << "[-] Driver command requested before command mutex was available." << std::endl;
        return false;
    }

    DWORD result = WaitForSingleObject(m_command_mutex, AEGIS2_COMMAND_TIMEOUT_MS);
    if (result == WAIT_OBJECT_0)
        return true;

    if (result == WAIT_ABANDONED)
    {
        std::cout << "[*] Previous AegisDriver2 client exited while holding the command mutex; recovering." << std::endl;
        return true;
    }

    std::cout << "[-] Timed out waiting for AegisDriver2 command mutex. wait_result=" << result
              << " GetLastError=" << GetLastError() << std::endl;
    return false;
}

void c_driver2::release_command_mutex()
{
    if (m_command_mutex && !ReleaseMutex(m_command_mutex))
    {
        std::cout << "[-] ReleaseMutex(command) failed. GetLastError=" << GetLastError() << std::endl;
    }
}

bool c_driver2::send_command()
{
    if (!m_shared || !m_request_event || !m_completion_event)
    {
        std::cout << "[-] Driver command requested before shared memory/events were connected." << std::endl;
        return false;
    }

    // Reset completion event, then signal request
    if (!ResetEvent(m_completion_event))
    {
        std::cout << "[-] ResetEvent(completion) failed. GetLastError=" << GetLastError() << std::endl;
        return false;
    }
    if (!SetEvent(m_request_event))
    {
        std::cout << "[-] SetEvent(request) failed. GetLastError=" << GetLastError() << std::endl;
        return false;
    }

    DWORD result = WaitForSingleObject(m_completion_event, AEGIS2_COMMAND_TIMEOUT_MS);
    if (result != WAIT_OBJECT_0)
    {
        std::cout << "[-] Driver command did not complete. wait_result=" << result
                  << " GetLastError=" << GetLastError() << std::endl;
        return false;
    }

    return true;
}

bool c_driver2::read_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !base || !buffer) return false;
    if (size == 0) return true;
    if (m_pid == 0)
    {
        std::cout << "[-] Driver read requested without an attached target PID." << std::endl;
        return false;
    }

    DWORD bytes_read = 0;
    while (bytes_read < size)
    {
        DWORD chunk_size = size - bytes_read;
        if (chunk_size > 0xFF00) chunk_size = 0xFF00;

        {
            command_lock guard(*this);
            if (!guard.locked()) return false;

            auto* cmd = (AEGIS2_COPY_MEMORY*)m_shared;
            memset(cmd, 0, sizeof(AEGIS2_COPY_MEMORY));
            prepare_aegis2_header(cmd->header, CMD_READ_MEMORY, m_pid);
            cmd->address = (unsigned long long)base + bytes_read;
            cmd->size = chunk_size;

            if (!send_command()) return false;
            if (cmd->header.status != STATUS_AEGIS_SUCCESS)
            {
                log_aegis2_failure("read", cmd->header);
                return false;
            }

            memcpy((PUCHAR)buffer + bytes_read, cmd->data, chunk_size);
        }

        bytes_read += chunk_size;
    }
    return true;
}

bool c_driver2::write_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared || !base || !buffer) return false;
    if (size == 0) return true;
    if (m_pid == 0)
    {
        std::cout << "[-] Driver write requested without an attached target PID." << std::endl;
        return false;
    }

    DWORD bytes_written = 0;
    while (bytes_written < size)
    {
        DWORD chunk_size = size - bytes_written;
        if (chunk_size > 0xFF00) chunk_size = 0xFF00;

        {
            command_lock guard(*this);
            if (!guard.locked()) return false;

            auto* cmd = (AEGIS2_COPY_MEMORY*)m_shared;
            memset(cmd, 0, sizeof(AEGIS2_COPY_MEMORY));
            prepare_aegis2_header(cmd->header, CMD_WRITE_MEMORY, m_pid);
            cmd->address = (unsigned long long)base + bytes_written;
            cmd->size = chunk_size;
            memcpy(cmd->data, (PUCHAR)buffer + bytes_written, chunk_size);

            if (!send_command()) return false;
            if (cmd->header.status != STATUS_AEGIS_SUCCESS)
            {
                log_aegis2_failure("write", cmd->header);
                return false;
            }
        }

        bytes_written += chunk_size;
    }
    return true;
}

PVOID c_driver2::alloc_memory_ex(DWORD size, DWORD protect)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return nullptr;
    if (size == 0)
    {
        std::cout << "[-] Driver alloc requested with size 0." << std::endl;
        return nullptr;
    }
    if (m_pid == 0)
    {
        std::cout << "[-] Driver alloc requested without an attached target PID." << std::endl;
        return nullptr;
    }

    command_lock guard(*this);
    if (!guard.locked()) return nullptr;

    auto* cmd = (AEGIS2_ALLOC_MEMORY*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_ALLOC_MEMORY));
    prepare_aegis2_header(cmd->header, CMD_ALLOC_MEMORY, m_pid);
    cmd->size = size;
    cmd->protect = protect;

    if (!send_command()) return nullptr;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("alloc", cmd->header);
        return nullptr;
    }

    return (PVOID)cmd->out_address;
}

bool c_driver2::free_memory_ex(PVOID address)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;
    if (!address)
    {
        std::cout << "[-] Driver free requested with a null address." << std::endl;
        return false;
    }
    if (m_pid == 0)
    {
        std::cout << "[-] Driver free requested without an attached target PID." << std::endl;
        return false;
    }

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_FREE_MEMORY*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_FREE_MEMORY));
    prepare_aegis2_header(cmd->header, CMD_FREE_MEMORY, m_pid);
    cmd->address = (unsigned long long)address;

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("free", cmd->header);
        return false;
    }
    return true;
}

bool c_driver2::create_remote_thread_ex(PVOID start_address, PVOID parameter, DWORD wait_ms)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;
    if (!start_address)
    {
        std::cout << "[-] Driver create-thread requested with a null start address." << std::endl;
        return false;
    }
    if (m_pid == 0)
    {
        std::cout << "[-] Driver create-thread requested without an attached target PID." << std::endl;
        return false;
    }

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_CREATE_THREAD*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_CREATE_THREAD));
    prepare_aegis2_header(cmd->header, CMD_CREATE_THREAD, m_pid);
    cmd->start_address = (unsigned long long)start_address;
    cmd->parameter = (unsigned long long)parameter;
    cmd->wait_ms = wait_ms;

    if (!send_command()) return false;
    if (cmd->header.status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("create-thread", cmd->header);
        return false;
    }
    return true;
}

bool c_driver2::ping()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_shared) return false;

    command_lock guard(*this);
    if (!guard.locked()) return false;

    auto* cmd = (AEGIS2_HEADER*)m_shared;
    memset(cmd, 0, sizeof(AEGIS2_HEADER));
    prepare_aegis2_header(*cmd, CMD_PING);

    if (!send_command()) return false;
    if (cmd->status != STATUS_AEGIS_SUCCESS)
    {
        log_aegis2_failure("ping", *cmd);
        return false;
    }
    return true;
}
