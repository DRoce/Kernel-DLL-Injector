#pragma once
#include <Windows.h>
#include <mutex>
#include "shared_defs.h"

class c_driver2
{
public:
    c_driver2();
    ~c_driver2();

    static c_driver2& singleton();

    bool     connect();           // Map shared section + open events
    void     disconnect();
    void     attach_process(DWORD pid);

    // Memory operations (same API as c_driver)
    bool     read_memory_ex(PVOID base, PVOID buffer, DWORD size);
    bool     write_memory_ex(PVOID base, PVOID buffer, DWORD size);
    PVOID    alloc_memory_ex(DWORD size, DWORD protect);
    bool     free_memory_ex(PVOID address);

    // Thread creation (NEW - fully kernel)
    bool     create_remote_thread_ex(PVOID start_address, PVOID parameter, DWORD wait_ms = 5000);

    // Ping to verify driver is alive
    bool     ping();

    bool     is_connected() const;
    DWORD    get_pid() const;

private:
    class command_lock
    {
    public:
        explicit command_lock(c_driver2& owner);
        ~command_lock();
        bool locked() const;

    private:
        c_driver2& m_owner;
        bool m_locked;
    };

    c_driver2(const c_driver2&) = delete;
    c_driver2& operator=(const c_driver2&) = delete;

    bool send_command();  // Signal request, wait for completion
    void disconnect_unlocked();
    bool acquire_command_mutex();
    void release_command_mutex();

    mutable std::mutex m_mutex;

    HANDLE  m_section;          // Shared memory section handle
    HANDLE  m_request_event;    // Signal driver to process
    HANDLE  m_completion_event; // Driver signals when done
    HANDLE  m_command_mutex;    // Cross-process shared command buffer guard
    void*   m_shared;           // Mapped view of shared memory
    DWORD   m_pid;              // Current target PID
};

inline c_driver2& driver2()
{
    return c_driver2::singleton();
}
