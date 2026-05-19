#pragma once
#include <Windows.h>
#include <iostream>

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID get_dll_by_file(LPCWSTR file_path)
{
	if (!file_path)
	{
		std::cout << "[-] DLL path pointer was null.\n";
		return NULL;
	}

	HANDLE h_dll = CreateFileW(
		file_path,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h_dll == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-] Failed to open DLL file. GetLastError=" << GetLastError() << "\n";
		return NULL; 
	}

	LARGE_INTEGER dll_file_sz_large = {};
	if (!GetFileSizeEx(h_dll, &dll_file_sz_large) ||
		dll_file_sz_large.QuadPart < sizeof(IMAGE_DOS_HEADER) ||
		dll_file_sz_large.QuadPart > MAXDWORD)
	{
		std::cout << "[-] Invalid DLL file size. size=" << dll_file_sz_large.QuadPart
			<< " GetLastError=" << GetLastError() << "\n";
		CloseHandle(h_dll);
		return NULL;
	}

	const DWORD dll_file_sz = static_cast<DWORD>(dll_file_sz_large.QuadPart);
	PVOID dll_buffer = VirtualAlloc(NULL, dll_file_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!dll_buffer)
	{
		std::cout << "[-] Failed to allocate local DLL buffer. size=" << dll_file_sz
			<< " GetLastError=" << GetLastError() << "\n";
		CloseHandle(h_dll);
		return NULL;
	}

	DWORD bytes_read = 0;
	if (!ReadFile(h_dll, dll_buffer, dll_file_sz, &bytes_read, NULL))
	{
		std::cout << "[-] Failed to read DLL file. GetLastError=" << GetLastError() << "\n";
		VirtualFree(dll_buffer, 0, MEM_RELEASE);
		dll_buffer = NULL;
	}
	else if (bytes_read != dll_file_sz)
	{
		std::cout << "[-] Short DLL read. expected=" << dll_file_sz << " actual=" << bytes_read << "\n";
		VirtualFree(dll_buffer, 0, MEM_RELEASE);
		dll_buffer = NULL;
	}
	else if (((PIMAGE_DOS_HEADER)dll_buffer)->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cout << "[-] DLL file does not start with MZ. signature=0x"
			<< std::hex << ((PIMAGE_DOS_HEADER)dll_buffer)->e_magic << std::dec << "\n";
		VirtualFree(dll_buffer, 0, MEM_RELEASE);
		dll_buffer = NULL;
	}

	CloseHandle(h_dll);
	return dll_buffer;
}

std::wstring to_fast_convert_wchar(PCCH a)
{
	std::wstring out_str;

	for (int i = 0; i < strlen(a) + 1; i++)
		out_str.push_back((const wchar_t)a[i]);

	return out_str;
}

DWORD get_process_id_and_thread_id_by_window_class(LPCSTR window_class_name, PDWORD p_thread_id)
{
	if (!window_class_name || !p_thread_id)
		return 0;

	DWORD process_id = 0;
	*p_thread_id = 0;

	const DWORD startTick = GetTickCount();
	while (!process_id && GetTickCount() - startTick < 10000)
	{
		HWND window = FindWindow(window_class_name, NULL);
		if (window)
			*p_thread_id = GetWindowThreadProcessId(window, &process_id);

		if (!process_id)
			Sleep(20);
	}

	return process_id;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD get_process_id_by_name(PCSTR name)
{
	DWORD pid = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	if (Process32First(snapshot, &process))
	{
		do
		{
			if (string(process.szExeFile) == string(name))
			{
				pid = process.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);
	return pid;
}

string get_process_name_by_pid(DWORD process_id)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);
	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return string();

	for (BOOL bok = Process32First(processesSnapshot, &processInfo); bok; bok = Process32Next(processesSnapshot, &processInfo))
	{
		if (process_id == processInfo.th32ProcessID)
		{
			string processName = processInfo.szExeFile;
			CloseHandle(processesSnapshot);
			return processName;
		}
	}

	CloseHandle(processesSnapshot);
	return string();
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
