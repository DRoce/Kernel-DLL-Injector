#pragma once
#include <Windows.h>
#include <atomic>
#include "driver/driver.h"
#include "driver/driver2.h"

// Global to track which driver backend is active.
// Keep this behind BackendKind helpers so invalid values fail closed instead of
// silently using EIQDV, and use atomic storage for future threaded callers.
extern std::atomic<int> g_active_driver;

namespace drv {
    enum class BackendKind : int {
        None = 0,
        EiqdvIoctl = 1,
        Aegis2SharedMemory = 2,
    };

    inline BackendKind active_backend() {
        switch (g_active_driver.load(std::memory_order_acquire)) {
        case 1: return BackendKind::EiqdvIoctl;
        case 2: return BackendKind::Aegis2SharedMemory;
        default: return BackendKind::None;
        }
    }

    inline bool set_backend(BackendKind backend) {
        switch (backend) {
        case BackendKind::EiqdvIoctl:
        case BackendKind::Aegis2SharedMemory:
            g_active_driver.store(static_cast<int>(backend), std::memory_order_release);
            return true;
        default:
            g_active_driver.store(static_cast<int>(BackendKind::None), std::memory_order_release);
            return false;
        }
    }

    inline const char* backend_name() {
        switch (active_backend()) {
        case BackendKind::EiqdvIoctl: return "EIQDV IOCTL";
        case BackendKind::Aegis2SharedMemory: return "AegisDriver2 Shared Memory";
        default: return "No valid backend";
        }
    }

    inline void attach(DWORD pid) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: driver2().attach_process(pid); break;
        case BackendKind::EiqdvIoctl: driver().attach_process(pid); break;
        default: break;
        }
    }
    inline PVOID alloc(DWORD size, DWORD protect) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().alloc_memory_ex(size, protect);
        case BackendKind::EiqdvIoctl: return driver().alloc_memory_ex(size, protect);
        default: return nullptr;
        }
    }
    inline bool write(PVOID base, PVOID buffer, DWORD size) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().write_memory_ex(base, buffer, size);
        case BackendKind::EiqdvIoctl: return driver().write_memory_ex(base, buffer, size) == 0;
        default: return false;
        }
    }
    inline bool read(PVOID base, PVOID buffer, DWORD size) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().read_memory_ex(base, buffer, size);
        case BackendKind::EiqdvIoctl: return driver().read_memory_ex(base, buffer, size) == 0;
        default: return false;
        }
    }
    inline bool free_mem(PVOID address) {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().free_memory_ex(address);
        case BackendKind::EiqdvIoctl: return driver().free_memory_ex(address) == 0;
        default: return false;
        }
    }
    inline bool is_loaded() {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().is_connected();
        case BackendKind::EiqdvIoctl: return driver().is_loaded();
        default: return false;
        }
    }
    inline bool ping() {
        switch (active_backend()) {
        case BackendKind::Aegis2SharedMemory: return driver2().ping();
        case BackendKind::EiqdvIoctl: return driver().is_loaded();
        default: return false;
        }
    }
    inline void disconnect() {
        const BackendKind backend = active_backend();
        if (backend == BackendKind::Aegis2SharedMemory)
            driver2().disconnect();
        else if (backend == BackendKind::EiqdvIoctl)
            driver().disconnect();
    }
}
