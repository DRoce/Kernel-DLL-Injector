#include "define/stdafx.h"
#include "api/xor.h"
#include "api/api.h"
#include "driver/driver.h"
#include "driver/driver2.h"
#include "drv_unified.h"
#include "inject.h"
#include "api/drvutils.h"
#include "manualmap.h"
#include "target.h"
#include <tlhelp32.h>

/*
    Aegis Loader - Kernel-Assisted DLL Injection Suite
    All memory operations routed through Aegis kernel driver.
    Supports two driver backends:
      - EIQDV (IOCTL-based)
      - AegisDriver2 (Shared Memory)
*/

// Global: which driver backend is active (1 = EIQDV, 2 = AegisDriver2)
std::atomic<int> g_active_driver{ 1 };

std::string GetDLLPath(std::string dllName)
{
	std::string dllPath;
	char tempPath[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), tempPath, (sizeof(tempPath)));
	PathRemoveFileSpec(tempPath);
	std::string path(tempPath);
	path += "\\" + dllName;
	return path;
}

static bool file_exists(const std::filesystem::path& path)
{
	std::error_code error;
	return std::filesystem::exists(path, error);
}

static void strip_surrounding_quotes(std::string& value)
{
	if (value.size() >= 2 &&
		((value.front() == '"' && value.back() == '"') ||
		 (value.front() == '\'' && value.back() == '\'')))
	{
		value = value.substr(1, value.size() - 2);
	}
}

static bool normalize_existing_dll_path(std::string& dllPath)
{
	strip_surrounding_quotes(dllPath);
	if (dllPath.empty())
	{
		std::cout << xor_a("[-] DLL path is empty.\n");
		return false;
	}
	if (!file_exists(std::filesystem::path(dllPath)))
	{
		std::cout << xor_a("[-] DLL path does not exist. Check the path and try again.\n");
		return false;
	}
	return true;
}

static std::wstring find_driver2_path()
{
	wchar_t modulePath[MAX_PATH] = { 0 };
	GetModuleFileNameW(nullptr, modulePath, ARRAYSIZE(modulePath));
	std::filesystem::path exeDir(modulePath);
	exeDir.remove_filename();

	wchar_t currentDirBuffer[MAX_PATH] = { 0 };
	GetCurrentDirectoryW(ARRAYSIZE(currentDirBuffer), currentDirBuffer);
	std::filesystem::path currentDir(currentDirBuffer);

	std::vector<std::filesystem::path> candidates = {
		exeDir / L"AegisDriver2.sys",
		exeDir.parent_path().parent_path() / L"AegisDriver2" / L"x64" / L"Release" / L"AegisDriver2.sys",
		currentDir / L"AegisDriver2" / L"x64" / L"Release" / L"AegisDriver2.sys",
		currentDir / L"x64" / L"Release" / L"AegisDriver2.sys",
	};

	for (const auto& candidate : candidates)
	{
		if (file_exists(candidate))
			return candidate.wstring();
	}

	return L"";
}

static bool wait_for_service_running(SC_HANDLE service, DWORD timeoutMs)
{
	const ULONGLONG deadline = GetTickCount64() + timeoutMs;
	SERVICE_STATUS_PROCESS status = {};
	DWORD bytesNeeded = 0;

	do
	{
		if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytesNeeded))
		{
			std::cout << "[-] QueryServiceStatusEx failed. GetLastError=" << GetLastError() << std::endl;
			return false;
		}

		if (status.dwCurrentState == SERVICE_RUNNING)
			return true;

		if (status.dwCurrentState == SERVICE_STOPPED)
		{
			std::cout << "[-] AegisDriver2 service stopped during startup. service_exit="
				<< status.dwWin32ExitCode << " specific_exit=" << status.dwServiceSpecificExitCode << std::endl;
			return false;
		}

		Sleep(100);
	} while (GetTickCount64() < deadline);

	std::cout << "[-] Timed out waiting for AegisDriver2 service to reach SERVICE_RUNNING. last_state="
		<< status.dwCurrentState << std::endl;
	return false;
}

static bool start_driver2_service()
{
	const std::wstring driverPath = find_driver2_path();
	if (driverPath.empty())
	{
		std::cout << "[-] Could not find AegisDriver2.sys in the expected build output paths." << std::endl;
		return false;
	}

	std::wcout << L"[*] Starting AegisDriver2 service from: " << driverPath << std::endl;

	SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
	if (!scm)
	{
		std::cout << "[-] OpenSCManagerW failed. GetLastError=" << GetLastError() << std::endl;
		return false;
	}

	const wchar_t* serviceName = L"AegisDriver2";
	SC_HANDLE service = CreateServiceW(
		scm,
		serviceName,
		serviceName,
		SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		driverPath.c_str(),
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		nullptr);

	if (!service && GetLastError() == ERROR_SERVICE_EXISTS)
	{
		service = OpenServiceW(scm, serviceName, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
		if (service)
		{
			ChangeServiceConfigW(
				service,
				SERVICE_KERNEL_DRIVER,
				SERVICE_DEMAND_START,
				SERVICE_ERROR_NORMAL,
				driverPath.c_str(),
				nullptr,
				nullptr,
				nullptr,
				nullptr,
				nullptr,
				nullptr);
		}
	}

	if (!service)
	{
		std::cout << "[-] Create/OpenServiceW failed. GetLastError=" << GetLastError() << std::endl;
		CloseServiceHandle(scm);
		return false;
	}

	if (!StartServiceW(service, 0, nullptr))
	{
		const DWORD startError = GetLastError();
		if (startError != ERROR_SERVICE_ALREADY_RUNNING)
		{
			std::cout << "[-] StartServiceW failed. GetLastError=" << startError << std::endl;
			CloseServiceHandle(service);
			CloseServiceHandle(scm);
			return false;
		}
	}

	const bool running = wait_for_service_running(service, 10000);

	CloseServiceHandle(service);
	CloseServiceHandle(scm);

	if (!running)
	{
		std::cout << "[-] AegisDriver2 service did not report SERVICE_RUNNING." << std::endl;
		return false;
	}

	return true;
}

static bool connect_driver2_with_retries(int attempts, DWORD delayMs)
{
	for (int attempt = 1; attempt <= attempts; ++attempt)
	{
		if (driver2().connect())
			return true;

		if (attempt < attempts)
			Sleep(delayMs);
	}

	return false;
}

void Inject_lol(int pID, std::string dllPath, bool can_manual_map, bool register_peb = false) {
	bool IsInjected = false;

	if (!can_manual_map) 
	{
		std::cout << xor_a("[-] Target process configuration prohibits Manual Map injection.") << std::endl;
		return;
	}

	manual_map mapper;
	IsInjected = mapper.inject_from_path(pID, dllPath.c_str(), register_peb);

	if (!IsInjected)
	{
		cout << xor_a("[-] Injection failed") << endl;
	}
}

static void* write_remote_dll_path(int pid, const std::string& dllPath)
{
	drv::attach(pid);
	void* loc = drv::alloc((DWORD)dllPath.length() + 1, PAGE_READWRITE);
	if (!loc)
	{
		std::cout << xor_a("[-] Kernel alloc failed. Is the driver loaded?\n");
		return nullptr;
	}

	if (!drv::write(loc, (PVOID)dllPath.c_str(), (DWORD)dllPath.length() + 1))
	{
		std::cout << xor_a("[-] Failed to write DLL path through selected backend.\n");
		drv::free_mem(loc);
		return nullptr;
	}

	std::cout << xor_a("[+] Path written via kernel at: 0x") << std::hex << (uintptr_t)loc << std::dec << std::endl;
	return loc;
}

static bool wait_remote_thread(HANDLE thread, DWORD timeoutMs, const char* operation)
{
	if (!thread)
		return false;

	DWORD waitResult = WaitForSingleObject(thread, timeoutMs);
	if (waitResult == WAIT_TIMEOUT)
	{
		std::cout << "[-] " << operation << " timed out after " << timeoutMs << "ms." << std::endl;
		CloseHandle(thread);
		return false;
	}
	if (waitResult != WAIT_OBJECT_0)
	{
		std::cout << "[-] " << operation << " wait failed. wait_result=" << waitResult
			<< " GetLastError=" << GetLastError() << std::endl;
		CloseHandle(thread);
		return false;
	}

	CloseHandle(thread);
	return true;
}

static void print_win32_failure(const char* operation, DWORD error)
{
	std::cout << "[-] " << operation << " failed. GetLastError=" << error;
	if (error == ERROR_ACCESS_DENIED)
		std::cout << " (Access denied)";
	else if (error == ERROR_INVALID_HANDLE)
		std::cout << " (Invalid handle)";
	else if (error == ERROR_NOT_SUPPORTED)
		std::cout << " (Not supported)";
	std::cout << std::endl;
}

static std::string trim_copy(const std::string& value)
{
	const size_t first = value.find_first_not_of(" \t\r\n");
	if (first == std::string::npos)
		return {};

	const size_t last = value.find_last_not_of(" \t\r\n");
	return value.substr(first, last - first + 1);
}

struct LoaderHistory
{
	std::string processHint;
	std::string windowClass;
	std::string dllPath;
	bool manualMapAllowed = true;
	bool pebRegistration = false;
};

static std::filesystem::path get_history_path()
{
	char localAppData[MAX_PATH] = {};
	const DWORD length = GetEnvironmentVariableA("LOCALAPPDATA", localAppData, ARRAYSIZE(localAppData));
	if (length > 0 && length < ARRAYSIZE(localAppData))
		return std::filesystem::path(localAppData) / "AegisLoader" / "loader_history.ini";

	return std::filesystem::current_path() / "loader_history.ini";
}

static bool parse_bool_value(const std::string& value, bool defaultValue)
{
	const std::string trimmed = trim_copy(value);
	if (_stricmp(trimmed.c_str(), "1") == 0 ||
		_stricmp(trimmed.c_str(), "true") == 0 ||
		_stricmp(trimmed.c_str(), "yes") == 0 ||
		_stricmp(trimmed.c_str(), "y") == 0)
		return true;

	if (_stricmp(trimmed.c_str(), "0") == 0 ||
		_stricmp(trimmed.c_str(), "false") == 0 ||
		_stricmp(trimmed.c_str(), "no") == 0 ||
		_stricmp(trimmed.c_str(), "n") == 0)
		return false;

	return defaultValue;
}

static const char* bool_to_text(bool value)
{
	return value ? "1" : "0";
}

static LoaderHistory load_loader_history()
{
	LoaderHistory history{};
	const std::filesystem::path historyPath = get_history_path();
	std::ifstream input(historyPath);
	if (!input)
		return history;

	std::string line;
	while (std::getline(input, line))
	{
		line = trim_copy(line);
		if (line.empty() || line[0] == '#')
			continue;

		const size_t separator = line.find('=');
		if (separator == std::string::npos)
			continue;

		const std::string key = trim_copy(line.substr(0, separator));
		std::string value = trim_copy(line.substr(separator + 1));
		strip_surrounding_quotes(value);

		if (_stricmp(key.c_str(), "process_hint") == 0)
			history.processHint = value;
		else if (_stricmp(key.c_str(), "window_class") == 0)
			history.windowClass = value;
		else if (_stricmp(key.c_str(), "dll_path") == 0)
			history.dllPath = value;
		else if (_stricmp(key.c_str(), "manual_map_allowed") == 0)
			history.manualMapAllowed = parse_bool_value(value, history.manualMapAllowed);
		else if (_stricmp(key.c_str(), "peb_registration") == 0)
			history.pebRegistration = parse_bool_value(value, history.pebRegistration);
	}

	return history;
}

static void save_loader_history(const LoaderHistory& history)
{
	const std::filesystem::path historyPath = get_history_path();
	std::error_code error;
	std::filesystem::create_directories(historyPath.parent_path(), error);
	if (error)
	{
		std::cout << xor_a("[!] Could not create history directory. error=") << error.message() << std::endl;
		return;
	}

	std::ofstream output(historyPath, std::ios::trunc);
	if (!output)
	{
		std::cout << xor_a("[!] Could not save loader history: ") << historyPath.string() << std::endl;
		return;
	}

	output << "process_hint=" << history.processHint << "\n";
	output << "window_class=" << history.windowClass << "\n";
	output << "dll_path=" << history.dllPath << "\n";
	output << "manual_map_allowed=" << bool_to_text(history.manualMapAllowed) << "\n";
	output << "peb_registration=" << bool_to_text(history.pebRegistration) << "\n";
}

static void print_loader_history_status(const LoaderHistory& history)
{
	if (history.processHint.empty() && history.windowClass.empty() && history.dllPath.empty())
		return;

	std::cout << xor_a("[+] Remembered defaults loaded from: ") << get_history_path().string() << std::endl;
	if (!history.processHint.empty())
		std::cout << xor_a("    Process/PID: ") << history.processHint << std::endl;
	if (!history.windowClass.empty())
		std::cout << xor_a("    Window Class: ") << history.windowClass << std::endl;
	if (!history.dllPath.empty())
		std::cout << xor_a("    DLL: ") << history.dllPath << std::endl;
}

static std::string prompt_text_with_default(const char* prompt, const std::string& rememberedValue)
{
	std::cout << prompt;
	if (!rememberedValue.empty())
		std::cout << xor_a(" [") << rememberedValue << xor_a("]");
	std::cout << xor_a(": ");

	std::string input;
	std::getline(std::cin >> std::ws, input);
	strip_surrounding_quotes(input);
	input = trim_copy(input);
	if (input.empty() && !rememberedValue.empty())
		return rememberedValue;

	return input;
}

static bool prompt_yes_no_with_default(const char* prompt, bool defaultValue)
{
	std::cout << prompt << (defaultValue ? xor_a(" (Y/n): ") : xor_a(" (y/N): "));
	std::string input;
	std::getline(std::cin >> std::ws, input);
	input = trim_copy(input);
	if (input.empty())
		return defaultValue;

	return input == "y" || input == "Y" || _stricmp(input.c_str(), "yes") == 0 || _stricmp(input.c_str(), "true") == 0 || input == "1";
}

static bool prompt_existing_dll_path(const char* prompt, const LoaderHistory& history, std::string& dllPath)
{
	dllPath = prompt_text_with_default(prompt, history.dllPath);
	if (dllPath.empty())
	{
		std::cout << xor_a("[-] DLL path is empty.\n");
		return false;
	}

	return normalize_existing_dll_path(dllPath);
}

static bool parse_pid_value(const std::string& input, DWORD& pid)
{
	try
	{
		size_t consumed = 0;
		const unsigned long value = std::stoul(input, &consumed, 0);
		if (consumed != input.size() || value == 0 || value > MAXDWORD)
			return false;

		pid = static_cast<DWORD>(value);
		return true;
	}
	catch (...)
	{
		return false;
	}
}

static DWORD find_process_id_by_name_case_insensitive(const std::string& processName, std::string* actualName)
{
	if (processName.empty())
		return 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(entry);

	DWORD pid = 0;
	if (Process32First(snapshot, &entry))
	{
		do
		{
			if (_stricmp(entry.szExeFile, processName.c_str()) == 0)
			{
				pid = entry.th32ProcessID;
				if (actualName)
					*actualName = entry.szExeFile;
				break;
			}
		} while (Process32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return pid;
}

static void print_auto_target_status(int pid, const TargetProcess& target)
{
	if (pid != -1)
	{
		std::cout << xor_a("[+] Auto target: ") << target.display_name
			<< xor_a(" | Process: ") << target.process_name
			<< xor_a(" | PID: ") << pid << std::endl;
		return;
	}

	std::cout << xor_a("[!] No configured Potential Targets process is currently detected.\n");
	std::cout << xor_a("[!] Process-based methods will ask for a PID or EXE name where supported.\n");
}

static int resolve_process_target_or_prompt(
	int autoPid,
	const TargetProcess& autoTarget,
	const char* methodName,
	bool allowManualTarget,
	const std::string& rememberedProcessHint,
	std::string* selectedProcessHint)
{
	if (autoPid != -1)
	{
		std::cout << xor_a("[+] Target: ") << autoTarget.display_name << std::endl;
		std::cout << xor_a("[+] Process: ") << autoTarget.process_name << std::endl;
		std::cout << xor_a("[+] Process ID: ") << autoPid << std::endl;
		if (selectedProcessHint)
			*selectedProcessHint = autoTarget.process_name;
		return autoPid;
	}

	std::cout << xor_a("[-] No Potential Targets match was found for ") << methodName << xor_a(".\n");
	if (!allowManualTarget)
	{
		std::cout << xor_a("[-] This method uses target-specific configuration and requires a configured Potential Targets match.\n");
		return -1;
	}

	std::string input = prompt_text_with_default("[>] Enter target Process ID or EXE name", rememberedProcessHint);
	if (input.empty())
		return -1;

	DWORD resolvedPid = 0;
	std::string resolvedName;
	if (parse_pid_value(input, resolvedPid))
	{
		resolvedName = get_process_name_by_pid(resolvedPid);
		if (resolvedName.empty())
		{
			std::cout << xor_a("[-] No running process was found for PID ") << resolvedPid << xor_a(".\n");
			return -1;
		}
	}
	else
	{
		resolvedPid = find_process_id_by_name_case_insensitive(input, &resolvedName);
		if (!resolvedPid && input.find('.') == std::string::npos)
		{
			const std::string exeName = input + ".exe";
			resolvedPid = find_process_id_by_name_case_insensitive(exeName, &resolvedName);
		}

		if (!resolvedPid)
		{
			std::cout << xor_a("[-] No running process was found for EXE name: ") << input << std::endl;
			return -1;
		}
	}

	std::cout << xor_a("[+] Target Process: ") << resolvedName << std::endl;
	std::cout << xor_a("[+] Process ID: ") << resolvedPid << std::endl;
	if (selectedProcessHint)
		*selectedProcessHint = input;
	return static_cast<int>(resolvedPid);
}

static bool find_window_thread_for_pid(DWORD pid, DWORD& threadId, HWND& window, bool& usedHiddenWindow)
{
	threadId = 0;
	window = nullptr;
	usedHiddenWindow = false;

	if (!pid)
		return false;

	DWORD fallbackThreadId = 0;
	HWND fallbackWindow = nullptr;
	for (HWND hw = GetTopWindow(nullptr); hw; hw = GetNextWindow(hw, GW_HWNDNEXT))
	{
		DWORD wndPid = 0;
		const DWORD tid = GetWindowThreadProcessId(hw, &wndPid);
		if (wndPid != pid || !tid)
			continue;

		if (IsWindowVisible(hw))
		{
			threadId = tid;
			window = hw;
			return true;
		}

		if (!fallbackThreadId)
		{
			fallbackThreadId = tid;
			fallbackWindow = hw;
		}
	}

	if (fallbackThreadId)
	{
		threadId = fallbackThreadId;
		window = fallbackWindow;
		usedHiddenWindow = true;
		return true;
	}

	return false;
}

static bool resolve_window_thread_target(
	int autoPid,
	const TargetProcess& autoTarget,
	int& resolvedPid,
	DWORD& threadId,
	const std::string& rememberedWindowClass,
	std::string* selectedWindowClass,
	std::string* selectedProcessHint)
{
	resolvedPid = -1;
	threadId = 0;
	if (selectedWindowClass)
		selectedWindowClass->clear();
	if (selectedProcessHint)
		selectedProcessHint->clear();

	if (autoPid != -1)
	{
		HWND window = nullptr;
		bool usedHiddenWindow = false;
		if (find_window_thread_for_pid(static_cast<DWORD>(autoPid), threadId, window, usedHiddenWindow))
		{
			std::cout << xor_a("[+] Target: ") << autoTarget.display_name << std::endl;
			std::cout << xor_a("[+] Process: ") << autoTarget.process_name << std::endl;
			std::cout << xor_a("[+] Process ID: ") << autoPid << std::endl;
			if (usedHiddenWindow)
				std::cout << xor_a("[*] No visible target window found; using hidden window thread.\n");
			resolvedPid = autoPid;
			if (selectedProcessHint)
				*selectedProcessHint = autoTarget.process_name;
			return true;
		}

		std::cout << xor_a("[-] Auto target was found, but no window thread was available for it.\n");
	}
	else
	{
		std::cout << xor_a("[-] No Potential Targets match was found for this window-thread injection path.\n");
	}

	std::string windowClass = prompt_text_with_default("[>] Enter target Window Class name", rememberedWindowClass);
	if (windowClass.empty())
		return false;

	DWORD foundThreadId = 0;
	const DWORD foundPid = get_process_id_and_thread_id_by_window_class(windowClass.c_str(), &foundThreadId);
	if (!foundPid || !foundThreadId)
	{
		std::cout << xor_a("[-] Could not find a process/window for class: ") << windowClass << std::endl;
		return false;
	}

	const std::string processName = get_process_name_by_pid(foundPid);
	std::cout << xor_a("[+] Target Window Class: ") << windowClass << std::endl;
	if (!processName.empty())
		std::cout << xor_a("[+] Target Process: ") << processName << std::endl;
	std::cout << xor_a("[+] Process ID: ") << foundPid << std::endl;

	resolvedPid = static_cast<int>(foundPid);
	threadId = foundThreadId;
	if (selectedWindowClass)
		*selectedWindowClass = windowClass;
	if (selectedProcessHint)
		*selectedProcessHint = processName.empty() ? std::to_string(foundPid) : processName;
	return true;
}

static bool run_driver_self_test()
{
	std::cout << xor_a("[*] Running driver memory self-test against this process...\n");

	if (!drv::is_loaded())
	{
		std::cout << xor_a("[-] Selected driver backend is not connected.\n");
		return false;
	}
	if (!drv::ping())
	{
		std::cout << xor_a("[-] Selected driver backend is connected, but not responding to ping.\n");
		return false;
	}
	std::cout << xor_a("[+] Driver ping passed.\n");

	const DWORD selfPid = GetCurrentProcessId();
	drv::attach(selfPid);

	constexpr DWORD testSize = 64;
	PVOID testAddress = drv::alloc(testSize, PAGE_READWRITE);
	if (!testAddress)
	{
		std::cout << xor_a("[-] Self-test alloc failed.\n");
		return false;
	}

	std::array<unsigned char, testSize> expected = {};
	std::array<unsigned char, testSize> actual = {};
	for (DWORD i = 0; i < testSize; ++i)
		expected[i] = static_cast<unsigned char>((i * 7) ^ 0xA5);

	bool passed = false;
	if (!drv::write(testAddress, expected.data(), testSize))
	{
		std::cout << xor_a("[-] Self-test write failed.\n");
	}
	else if (!drv::read(testAddress, actual.data(), testSize))
	{
		std::cout << xor_a("[-] Self-test read failed.\n");
	}
	else if (memcmp(expected.data(), actual.data(), testSize) != 0)
	{
		std::cout << xor_a("[-] Self-test data mismatch.\n");
	}
	else
	{
		passed = true;
		std::cout << xor_a("[+] Self-test passed. Driver alloc/write/read/free path is working.\n");
	}

	if (!drv::free_mem(testAddress))
		std::cout << xor_a("[!] Self-test cleanup warning: remote free failed.\n");

	return passed;
}

static bool run_driver_negative_self_test()
{
	std::cout << xor_a("[*] Running driver invalid-request self-test against this process...\n");

	if (!drv::is_loaded())
	{
		std::cout << xor_a("[-] Selected driver backend is not connected.\n");
		return false;
	}
	if (!drv::ping())
	{
		std::cout << xor_a("[-] Selected driver backend is connected, but not responding to ping.\n");
		return false;
	}

	std::cout << xor_a("[*] The next requests are expected to fail cleanly.\n");

	const DWORD selfPid = GetCurrentProcessId();
	drv::attach(selfPid);

	std::array<unsigned char, 16> buffer = {};
	bool passed = true;

	if (drv::read((PVOID)1, buffer.data(), (DWORD)buffer.size()))
	{
		std::cout << xor_a("[-] Invalid-address read unexpectedly succeeded.\n");
		passed = false;
	}
	else
	{
		std::cout << xor_a("[+] Invalid-address read failed cleanly.\n");
	}

	if (drv::write((PVOID)1, buffer.data(), (DWORD)buffer.size()))
	{
		std::cout << xor_a("[-] Invalid-address write unexpectedly succeeded.\n");
		passed = false;
	}
	else
	{
		std::cout << xor_a("[+] Invalid-address write failed cleanly.\n");
	}

	drv::attach(0);
	PVOID invalidAlloc = drv::alloc(16, PAGE_READWRITE);
	if (invalidAlloc)
	{
		std::cout << xor_a("[-] Invalid-PID alloc unexpectedly succeeded.\n");
		drv::attach(selfPid);
		drv::free_mem(invalidAlloc);
		passed = false;
	}
	else
	{
		std::cout << xor_a("[+] Invalid-PID alloc failed cleanly.\n");
		drv::attach(selfPid);
	}

	if (passed)
		std::cout << xor_a("[+] Invalid-request self-test passed. Failure paths are returning errors cleanly.\n");

	return passed;
}

int main()
{
	std::string targetClass;
	std::string reply;

	std::cout << xor_a("==================================================") << std::endl;
	std::cout << xor_a("             Aegis Loader - Driver Setup          ") << std::endl;
	std::cout << xor_a("==================================================") << std::endl;
	std::cout << xor_a("[1] EIQDV Driver (IOCTL - Default)") << std::endl;
	std::cout << xor_a("[2] AegisDriver2 (Shared Memory - Stealth)") << std::endl;
	std::cout << xor_a("[>] Select driver backend: ");
	
	std::string driver_choice;
	std::cin >> driver_choice;
	
	if (driver_choice == "2") {
		drv::set_backend(drv::BackendKind::Aegis2SharedMemory);
		std::cout << xor_a("[*] Connecting to AegisDriver2 via shared memory...") << std::endl;
		if (!connect_driver2_with_retries(1, 0)) {
			std::cout << xor_a("[-] AegisDriver2 not loaded. Trying service load now...") << std::endl;
			const bool serviceStarted = start_driver2_service();
			if (!serviceStarted)
				std::cout << xor_a("[*] Service path unavailable; mapper fallback will be tried next.\n");

			if (!connect_driver2_with_retries(10, 250)) {
				std::cout << xor_a("[-] Service path did not expose AegisDriver2 shared memory. Mapping driver now...") << std::endl;
				if (!map_driver2()) {
					std::cout << xor_a("[-] Failed to launch AegisDriver2 mapper.") << std::endl;
					system("pause");
					return 1;
				}

				if (!connect_driver2_with_retries(20, 250)) {
					std::cout << xor_a("[-] Failed to load and connect to AegisDriver2.") << std::endl;
					system("pause");
					return 1;
				}
			}
		}
		if (!drv::ping()) {
			std::cout << xor_a("[-] AegisDriver2 shared objects opened, but the worker did not respond to ping.") << std::endl;
			system("pause");
			return 1;
		}
		std::cout << xor_a("[+] AegisDriver2 initialized successfully!") << std::endl;
	} else {
		drv::set_backend(drv::BackendKind::EiqdvIoctl);
		std::cout << xor_a("[*] Initializing EIQDV driver...") << std::endl;
		if (!start_driver()) {
			std::cout << xor_a("[-] Failed to initialize EIQDV backend.") << std::endl;
			system("pause");
			return 1;
		}
	}
	std::cout << xor_a("[+] Active backend: ") << drv::backend_name() << std::endl;

	cout << endl;

	Target::print_potential_targets();

	TargetProcess target{};
	int pid = Target::find_target(&target);
	LoaderHistory history = load_loader_history();
	string dllPath = pid != -1 ? GetDLLPath(target.dll_name) : string();

	system(xor_a("CLS"));

	std::cout << xor_a("[+] Active backend: ") << drv::backend_name() << std::endl;
	print_auto_target_status(pid, target);
	print_loader_history_status(history);
	std::cout << std::endl;

	std::cout << xor_a("[*] Select Injection Method:") << xor_a("\n");
	std::cout << xor_a("    [1] ManualMap (Auto-detects or prompts for target info)") << xor_a("\n");
	std::cout << xor_a("    [2] Kernel Hook Injection (Uses specified Window Class)") << std::endl;
	std::cout << xor_a("    [3] Kernel LoadLibrary + CreateRemoteThread") << std::endl;
	std::cout << xor_a("    [4] Kernel LoadLibrary + NtCreateThreadEx") << std::endl;
	std::cout << xor_a("    [5] Kernel LoadLibrary + QueueUserAPC") << std::endl;
	std::cout << xor_a("    [6] Kernel LoadLibrary + RtlCreateUserThread") << std::endl;
	std::cout << xor_a("    [7] Kernel LoadLibrary + Thread Hijack") << std::endl;
	std::cout << xor_a("    [8] Kernel LoadLibrary (Driver-assisted, most stealth)") << std::endl;
	std::cout << xor_a("    [9] Driver memory self-test (local process)") << std::endl;
	std::cout << xor_a("    [10] Driver invalid-request self-test (local process)") << std::endl;
	std::cout << xor_a("[>] Option (1-10): ");
	std::cin >> reply;

	/* if reply = 1 (manualmap) */
	if (reply == xor_a("1"))
	{
		std::string selectedProcessHint;
		const int selectedPid = resolve_process_target_or_prompt(pid, target, "ManualMap", true, history.processHint, &selectedProcessHint);
		if (selectedPid != -1)
		{
			std::string manualDllName;
			if (!prompt_existing_dll_path("[>] Enter target DLL path (e.g. C:\\path\\to\\target.dll)", history, manualDllName))
			{
				Sleep(-1);
				return 0;
			}
			dllPath = manualDllName;

			printf(xor_a("[+] DLL Path: %s \n"), dllPath.c_str());

			bool canManualMap = target.manual_map;
			if (pid == -1)
			{
				std::cout << xor_a("[!] This target was not loaded from Potential Targets.\n");
				canManualMap = prompt_yes_no_with_default("[>] Confirm this target supports ManualMap", history.manualMapAllowed);
			}
			else if (!target.manual_map)
			{
				std::cout << xor_a("[!] Potential Targets marks ManualMap unsupported for this process.\n");
				canManualMap = prompt_yes_no_with_default("[>] Override and try ManualMap anyway", false);
			}

			bool enablePeb = prompt_yes_no_with_default("[>] Enable PEB registration? Makes DLL visible to GetModuleHandle", history.pebRegistration);
			if (enablePeb)
				std::cout << xor_a("[+] PEB registration enabled.\n");

			history.processHint = selectedProcessHint;
			history.dllPath = dllPath;
			history.manualMapAllowed = canManualMap;
			history.pebRegistration = enablePeb;
			save_loader_history(history);

			Inject_lol(selectedPid, dllPath, canManualMap, enablePeb);

			Sleep(-1);
		}
		else 
		{
			std::cout << xor_a("[-] Couldn't find any valid target process.\n");
		}

	}

	/* if reply = 2 (default one) */
	else if (reply == xor_a("2"))
	{
		std::cout << xor_a("[+] Injection Method: Kernel Hook Injection\n");
		targetClass = prompt_text_with_default("[>] Enter target Window Class name (e.g. UnrealWindow)", history.windowClass);
		if (targetClass.empty())
		{
			std::cout << xor_a("[-] Target Window Class is empty.\n");
			Sleep(-1);
			return 0;
		}
		std::cout << xor_a("[+] Target Window Class: ") << targetClass << std::endl;
		
		std::string faceDllName;
		if (!prompt_existing_dll_path("[>] Enter target DLL path (e.g. C:\\path\\to\\target.dll)", history, faceDllName))
		{
			Sleep(-1);
			return 0;
		}
		std::wstring wFaceDllName = std::filesystem::path(faceDllName).wstring();

		history.windowClass = targetClass;
		history.dllPath = faceDllName;
		save_loader_history(history);

		std::cout << xor_a("[+] Target DLL: ") << faceDllName << std::endl;
		std::cout << xor_a("[*] Executing injection...\n");

		inject(targetClass.c_str(), wFaceDllName.c_str());
		
		std::cout << xor_a("[+] Injection call completed.\n");
		Sleep(-1);
	}

	else if (reply == xor_a("3"))
	{
		std::cout << xor_a("[+] Injection Method: Kernel LoadLibrary + CreateRemoteThread\n");
		std::string selectedProcessHint;
		const int selectedPid = resolve_process_target_or_prompt(pid, target, "Kernel LoadLibrary + CreateRemoteThread", true, history.processHint, &selectedProcessHint);
		if (selectedPid != -1)
		{
			std::string dllName;
			if (!prompt_existing_dll_path("[>] Enter target DLL path", history, dllName))
			{
				Sleep(-1);
				return 0;
			}
			history.processHint = selectedProcessHint;
			history.dllPath = dllName;
			save_loader_history(history);

			std::cout << xor_a("[*] Allocating via kernel driver...\n");
			void* loc = write_remote_dll_path(selectedPid, dllName);
			if (loc)
			{
				HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | SYNCHRONIZE, FALSE, selectedPid);
				if (hProc) {
					SetLastError(ERROR_SUCCESS);
					HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
					if (hThread && wait_remote_thread(hThread, 10000, "CreateRemoteThread")) { std::cout << xor_a("[+] Injection completed successfully.\n"); }
					else if (!hThread) { print_win32_failure("CreateRemoteThread", GetLastError()); }
					else { std::cout << xor_a("[-] CreateRemoteThread did not complete successfully.\n"); }
					CloseHandle(hProc);
				}
				else { print_win32_failure("OpenProcess(PROCESS_CREATE_THREAD)", GetLastError()); }
				drv::free_mem(loc);
			}
		}
		else { std::cout << xor_a("[-] Couldn't find any valid target process.\n"); }
		Sleep(-1);
	}
	else if (reply == xor_a("4"))
	{
		std::cout << xor_a("[+] Injection Method: Kernel LoadLibrary + NtCreateThreadEx\n");
		std::string selectedProcessHint;
		const int selectedPid = resolve_process_target_or_prompt(pid, target, "Kernel LoadLibrary + NtCreateThreadEx", true, history.processHint, &selectedProcessHint);
		if (selectedPid != -1)
		{
			std::string dllName;
			if (!prompt_existing_dll_path("[>] Enter target DLL path", history, dllName))
			{
				Sleep(-1);
				return 0;
			}
			history.processHint = selectedProcessHint;
			history.dllPath = dllName;
			save_loader_history(history);

			std::cout << xor_a("[*] Allocating via kernel driver...\n");
			void* loc = write_remote_dll_path(selectedPid, dllName);
			if (loc)
			{
				HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | SYNCHRONIZE, FALSE, selectedPid);
				if (hProc)
				{
					auto pNtCreateThreadEx = (long(__stdcall*)(HANDLE*, ACCESS_MASK, void*, HANDLE, void*, void*, ULONG, SIZE_T, SIZE_T, SIZE_T, void*))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
					if (pNtCreateThreadEx)
					{
						HANDLE hThread = nullptr;
						long status = pNtCreateThreadEx(&hThread, GENERIC_ALL, nullptr, hProc, (void*)LoadLibraryA, loc, 0, 0, 0, 0, nullptr);
						if (status == 0 && hThread && wait_remote_thread(hThread, 10000, "NtCreateThreadEx")) { std::cout << xor_a("[+] Injection completed successfully.\n"); }
						else
						{
							std::cout << xor_a("[-] NtCreateThreadEx failed or did not complete. NTSTATUS=0x")
								<< std::hex << status << std::dec;
							if (status == 0xC0000022L)
								std::cout << xor_a(" (STATUS_ACCESS_DENIED)");
							std::cout << xor_a(" hThread=") << hThread << std::endl;
						}
					}
					else { std::cout << xor_a("[-] NtCreateThreadEx was not available.\n"); }
					CloseHandle(hProc);
				}
				else { print_win32_failure("OpenProcess(PROCESS_CREATE_THREAD)", GetLastError()); }
				drv::free_mem(loc);
			}
		}
		else { std::cout << xor_a("[-] Couldn't find any valid target process.\n"); }
		Sleep(-1);
	}
	else if (reply == xor_a("5"))
	{
		std::cout << xor_a("[+] Injection Method: Kernel LoadLibrary + QueueUserAPC\n");
		std::string selectedProcessHint;
		const int selectedPid = resolve_process_target_or_prompt(pid, target, "Kernel LoadLibrary + QueueUserAPC", true, history.processHint, &selectedProcessHint);
		if (selectedPid != -1)
		{
			std::string dllName;
			if (!prompt_existing_dll_path("[>] Enter target DLL path", history, dllName))
			{
				Sleep(-1);
				return 0;
			}
			history.processHint = selectedProcessHint;
			history.dllPath = dllName;
			save_loader_history(history);

			std::cout << xor_a("[*] Allocating via kernel driver...\n");
			void* loc = write_remote_dll_path(selectedPid, dllName);
			if (loc)
			{
				bool keepPathBuffer = false;
				HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
				if (hSnapshot != INVALID_HANDLE_VALUE)
				{
					THREADENTRY32 te32;
					te32.dwSize = sizeof(THREADENTRY32);
					bool injected = false;
					if (Thread32First(hSnapshot, &te32))
					{
						do {
							if (te32.th32OwnerProcessID == static_cast<DWORD>(selectedPid))
							{
								HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
								if (hThread) { QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)loc); CloseHandle(hThread); injected = true; }
							}
						} while (Thread32Next(hSnapshot, &te32));
					}
					CloseHandle(hSnapshot);
					if (injected) {
						keepPathBuffer = true;
						std::cout << xor_a("[+] APCs queued. DLL will load when a thread enters an alertable state.\n");
					}
					else std::cout << xor_a("[-] Failed to queue APCs to any thread.\n");
				}
				else
				{
					std::cout << xor_a("[-] Failed to enumerate target threads.\n");
				}
				// APC delivery is asynchronous; free only when no APC was staged.
				// The successful path intentionally keeps the path buffer valid for queued APCs.
				// It is reclaimed when the target process exits.
				if (!keepPathBuffer)
					drv::free_mem(loc);
			}
		}
		else { std::cout << xor_a("[-] Couldn't find any valid target process.\n"); }
		Sleep(-1);
	}
	else if (reply == xor_a("6"))
	{
		std::cout << xor_a("[+] Injection Method: Kernel LoadLibrary + RtlCreateUserThread\n");
		std::string selectedProcessHint;
		const int selectedPid = resolve_process_target_or_prompt(pid, target, "Kernel LoadLibrary + RtlCreateUserThread", true, history.processHint, &selectedProcessHint);
		if (selectedPid != -1)
		{
			std::string dllName;
			if (!prompt_existing_dll_path("[>] Enter target DLL path", history, dllName))
			{
				Sleep(-1);
				return 0;
			}
			history.processHint = selectedProcessHint;
			history.dllPath = dllName;
			save_loader_history(history);

			std::cout << xor_a("[*] Allocating via kernel driver...\n");
			void* loc = write_remote_dll_path(selectedPid, dllName);
			if (loc)
			{
				HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | SYNCHRONIZE, FALSE, selectedPid);
				if (hProc)
				{
					auto pRtlCreateUserThread = (long(__stdcall*)(HANDLE, void*, BOOLEAN, ULONG, SIZE_T, SIZE_T, void*, void*, HANDLE*, void*))GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
					if (pRtlCreateUserThread)
					{
						HANDLE hThread = nullptr;
						long status = pRtlCreateUserThread(hProc, nullptr, FALSE, 0, 0, 0, (void*)LoadLibraryA, loc, &hThread, nullptr);
						if (status == 0 && hThread && wait_remote_thread(hThread, 10000, "RtlCreateUserThread")) { std::cout << xor_a("[+] Injection completed successfully.\n"); }
						else { std::cout << xor_a("[-] Failed to create thread via RtlCreateUserThread.\n"); }
					}
					else { std::cout << xor_a("[-] RtlCreateUserThread was not available.\n"); }
					CloseHandle(hProc);
				}
				else { std::cout << xor_a("[-] OpenProcess failed. GetLastError=") << GetLastError() << std::endl; }
				drv::free_mem(loc);
			}
		}
		else { std::cout << xor_a("[-] Couldn't find any valid target process.\n"); }
		Sleep(-1);
	}
	else if (reply == xor_a("7"))
	{
		std::cout << xor_a("[+] Injection Method: Kernel LoadLibrary + Thread Hijack\n");
		std::string selectedProcessHint;
		const int selectedPid = resolve_process_target_or_prompt(pid, target, "Kernel LoadLibrary + Thread Hijack", true, history.processHint, &selectedProcessHint);
		if (selectedPid != -1)
		{
			std::string dllName;
			if (!prompt_existing_dll_path("[>] Enter target DLL path", history, dllName))
			{
				Sleep(-1);
				return 0;
			}
			history.processHint = selectedProcessHint;
			history.dllPath = dllName;
			save_loader_history(history);

			std::cout << xor_a("[*] Allocating via kernel driver...\n");
			void* loc = write_remote_dll_path(selectedPid, dllName);
			if (loc)
			{
				bool keepPathBuffer = false;
				HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
				if (hSnapshot != INVALID_HANDLE_VALUE)
				{
					THREADENTRY32 te32;
					te32.dwSize = sizeof(THREADENTRY32);
					DWORD threadId = 0;
					if (Thread32First(hSnapshot, &te32))
					{
						do {
							if (te32.th32OwnerProcessID == static_cast<DWORD>(selectedPid)) { threadId = te32.th32ThreadID; break; }
						} while (Thread32Next(hSnapshot, &te32));
					}
					CloseHandle(hSnapshot);
					if (threadId)
					{
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
						if (hThread)
						{
							DWORD suspendResult = SuspendThread(hThread);
							if (suspendResult == (DWORD)-1)
							{
								std::cout << xor_a("[-] SuspendThread failed. GetLastError=") << GetLastError() << std::endl;
								CloseHandle(hThread);
							}
							else
							{
								CONTEXT ctx = {};
								ctx.ContextFlags = CONTEXT_FULL;
								if (GetThreadContext(hThread, &ctx))
								{
									uint8_t shellcode[] = {
										0x9C, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
										0x48, 0x89, 0xE3,
										0x48, 0x83, 0xE4, 0xF0,
										0x48, 0x83, 0xEC, 0x20,
										0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
										0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
										0xFF, 0xD0,
										0x48, 0x89, 0xDC,
										0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B, 0x58, 0x9D,
										0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
										0xFF, 0xE0
									};
									*(uintptr_t*)(shellcode + 26) = (uintptr_t)loc;
									*(uintptr_t*)(shellcode + 36) = (uintptr_t)LoadLibraryA;
									*(uintptr_t*)(shellcode + 64) = (uintptr_t)ctx.Rip;
									void* shellcode_loc = drv::alloc(sizeof(shellcode), PAGE_EXECUTE_READWRITE);
									if (shellcode_loc)
									{
										if (drv::write(shellcode_loc, shellcode, sizeof(shellcode)))
										{
											ctx.Rip = (uintptr_t)shellcode_loc;
											if (SetThreadContext(hThread, &ctx))
											{
												keepPathBuffer = true;
												std::cout << xor_a("[+] Thread hijacked to load DLL.\n");
											}
											else
												std::cout << xor_a("[-] SetThreadContext failed. GetLastError=") << GetLastError() << std::endl;
										}
										else
										{
											std::cout << xor_a("[-] Kernel write for shellcode failed.\n");
											drv::free_mem(shellcode_loc);
										}
									}
									else { std::cout << xor_a("[-] Kernel alloc for shellcode failed.\n"); }
								}
								else { std::cout << xor_a("[-] GetThreadContext failed. GetLastError=") << GetLastError() << std::endl; }
								ResumeThread(hThread);
								CloseHandle(hThread);
							}
						}
						else { std::cout << xor_a("[-] OpenThread failed. GetLastError=") << GetLastError() << std::endl; }
					}
					else { std::cout << xor_a("[-] No target thread found for hijack.\n"); }
				}
				else
				{
					std::cout << xor_a("[-] Failed to enumerate target threads.\n");
				}
				if (!keepPathBuffer)
					drv::free_mem(loc);
			}
		}
		else { std::cout << xor_a("[-] Couldn't find any valid target process.\n"); }
		Sleep(-1);
	}
	else if (reply == xor_a("8"))
	{
		std::cout << xor_a("[+] Injection Method: Kernel-Assisted LoadLibrary\n");
		std::cout << xor_a("[+] Uses Aegis driver for memory ops + SetWindowsHookEx for execution\n");

		if (!drv::is_loaded())
		{
			std::cout << xor_a("[-] Selected Aegis driver backend is NOT connected!\n");
			std::cout << xor_a("[-] Use the Driver Setup screen first, then choose injection option 8.\n");
			Sleep(-1);
			return 0;
		}
		std::cout << xor_a("[+] Selected Aegis driver backend is connected.\n");

		int selectedPid = -1;
		DWORD threadId = 0;
		std::string selectedWindowClass;
		std::string selectedProcessHint;
		if (resolve_window_thread_target(pid, target, selectedPid, threadId, history.windowClass, &selectedWindowClass, &selectedProcessHint))
		{
			std::string kernelDllPath;
			if (!prompt_existing_dll_path("[>] Enter target DLL path", history, kernelDllPath))
			{
				Sleep(-1);
				return 0;
			}
			std::cout << xor_a("[+] DLL Path: ") << kernelDllPath << std::endl;

			if (!selectedProcessHint.empty())
				history.processHint = selectedProcessHint;
			if (!selectedWindowClass.empty())
				history.windowClass = selectedWindowClass;
			history.dllPath = kernelDllPath;
			save_loader_history(history);

			// Attach driver to the target process
			drv::attach(selectedPid);

			std::cout << xor_a("[+] Thread ID: 0x") << std::hex << threadId << std::dec << std::endl;

			// Use the kernel driver's call_remote_load_library:
			// - Allocates shellcode memory via driver (kernel)
			// - Writes shellcode + data via driver (kernel)
			// - Executes via SetWindowsHookEx (no CreateRemoteThread)
			// - LoadLibraryA does the actual loading (full OS loader support)
			std::cout << xor_a("[+] Injecting via kernel memory ops + SetWindowsHookEx...\n");
			uintptr_t result = call_remote_load_library(threadId, kernelDllPath.c_str());

			if (result)
			{
				std::cout << xor_a("[+] DLL loaded at: 0x") << std::hex << result << std::endl;
				std::cout << xor_a("[+] Kernel-assisted injection successful!\n");
			}
			else
			{
				std::cout << xor_a("[-] Kernel-assisted injection failed.\n");
			}
		}
		else
		{
			std::cout << xor_a("[-] No target window/thread was selected.\n");
		}
		Sleep(-1);
	}
	else if (reply == xor_a("9"))
	{
		run_driver_self_test();
		Sleep(-1);
	}
	else if (reply == xor_a("10"))
	{
		run_driver_negative_self_test();
		Sleep(-1);
	}
	else
	{
		std::cout << xor_a("[-] Invalid Selection.") << std::endl;
		Sleep(-1);
	}

	/* Calling injection in specified Class name and default dll (can be changed) */
	

	cout << endl;
	Sleep(-1);
}


/*
    
    Added a class finder, directly ask you the class name of the process that you want to inject in.

*/
