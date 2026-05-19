#pragma once
#include "shellcode.h"
#include "shell_aegis2.h"
#include <random>
#include <mutex>

#define patch_shell   xor_w(L"\\SoftwareDistribution\\Download\\")

string random_string()
{
	static std::mt19937 rng(std::random_device{}());
	static std::mutex rng_mutex;
	static const string str = xor_a("QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
	std::uniform_int_distribution<size_t> dist(0, str.size() - 1);
	string newstr;
	std::lock_guard<std::mutex> lock(rng_mutex);
	while (newstr.size() != 32)
	{
		newstr.push_back(str[dist(rng)]);
	}
	return newstr;
}

wstring random_string_w()
{
	static std::mt19937 rng(std::random_device{}());
	static std::mutex rng_mutex;
	static const wstring str = xor_w(L"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890");
	std::uniform_int_distribution<size_t> dist(0, str.size() - 1);
	wstring newstr;
	std::lock_guard<std::mutex> lock(rng_mutex);
	while (newstr.size() != 5)
	{
		newstr.push_back(str[dist(rng)]);
	}
	return newstr;
}

wstring get_parent(const wstring& path)
{
	if (path.empty())
		return path;

	auto idx = path.rfind(L'\\');
	if (idx == path.npos)
		idx = path.rfind(L'/');

	if (idx != path.npos)
		return path.substr(0, idx);
	else
		return path;
}

wstring get_exe_directory()
{
	wchar_t imgName[MAX_PATH] = { 0 };
	DWORD len = ARRAYSIZE(imgName);
	QueryFullProcessImageNameW(GetCurrentProcess(), 0, imgName, &len);
	wstring sz_dir = (wstring(get_parent(imgName)) + xor_w(L"\\"));
	return sz_dir;
}

wstring get_files_directory()
{
	WCHAR system_dir[256];
	if (!GetWindowsDirectoryW(system_dir, 256))
		return L"";
	wstring sz_dir = (wstring(system_dir) + xor_w(L"\\SoftwareDistribution\\Download\\"));
	return sz_dir;
}

bool ensure_directory_exists(const wstring& directory)
{
	if (directory.empty())
		return false;

	DWORD attributes = GetFileAttributesW(directory.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES)
		return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

	return CreateDirectoryW(directory.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

wstring get_random_file_name_directory(wstring type_file)
{
	wstring sz_file = get_files_directory() + random_string_w() + type_file;
	return sz_file;
}

bool run_us_admin(std::wstring sz_exe, bool show)
{
	return (INT_PTR)ShellExecuteW(NULL, xor_w(L"runas"), sz_exe.c_str(), NULL, NULL, show) > 32;
}

bool run_us_admin_and_params(wstring sz_exe, wstring sz_params, bool show)
{
	return (INT_PTR)ShellExecuteW(NULL, xor_w(L"runas"), sz_exe.c_str(), sz_params.c_str(), NULL, show) > 32;
}

bool drop_payload(const wstring& path, const void* payload, DWORD payload_size)
{
	if (!payload || payload_size == 0)
		return false;

	HANDLE h_file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	DWORD byte = 0;
	BOOL b_status = WriteFile(h_file, payload, payload_size, &byte, nullptr);
	CloseHandle(h_file);

	return b_status && byte == payload_size;
}

bool drop_mapper(wstring path)
{
	return drop_payload(path, shell_mapper, (DWORD)sizeof(shell_mapper));
}

bool drop_driver(wstring path)
{
	return drop_payload(path, shell_driver, (DWORD)sizeof(shell_driver));
}

bool drop_driver2(wstring path)
{
	return drop_payload(path, shell_aegis_driver2, (DWORD)sizeof(shell_aegis_driver2));
}

wstring get_files_path()
{
	WCHAR system_dir[256];
	GetWindowsDirectoryW(system_dir, 256);
	return (wstring(system_dir) + patch_shell);
}

bool map_driver()
{
	if (!ensure_directory_exists(get_files_directory()))
		return false;

	wstring sz_driver = get_random_file_name_directory(xor_w(L".sys"));
	wstring sz_mapper = get_random_file_name_directory(xor_w(L".exe"));
	wstring sz_params_map = xor_w(L"-map ") + sz_driver;

	/* Delete files */
	DeleteFileW(sz_driver.c_str());
	DeleteFileW(sz_mapper.c_str());

	Sleep(1000);

	if (!drop_driver(sz_driver) || !drop_mapper(sz_mapper))
	{
		DeleteFileW(sz_driver.c_str());
		DeleteFileW(sz_mapper.c_str());
		return false;
	}

	if (!run_us_admin_and_params(sz_mapper, sz_params_map, false))
	{
		DeleteFileW(sz_driver.c_str());
		DeleteFileW(sz_mapper.c_str());
		return false;
	}
	Sleep(6000);

	DeleteFileW(sz_driver.c_str());
	DeleteFileW(sz_mapper.c_str());
	return true;
}

bool map_driver2()
{
	if (!ensure_directory_exists(get_files_directory()))
		return false;

	wstring sz_driver = get_random_file_name_directory(xor_w(L".sys"));
	wstring sz_mapper = get_random_file_name_directory(xor_w(L".exe"));
	wstring sz_params_map = xor_w(L"-map ") + sz_driver;

	DeleteFileW(sz_driver.c_str());
	DeleteFileW(sz_mapper.c_str());

	Sleep(1000);

	if (!drop_driver2(sz_driver) || !drop_mapper(sz_mapper))
	{
		DeleteFileW(sz_driver.c_str());
		DeleteFileW(sz_mapper.c_str());
		return false;
	}

	if (!run_us_admin_and_params(sz_mapper, sz_params_map, false))
	{
		DeleteFileW(sz_driver.c_str());
		DeleteFileW(sz_mapper.c_str());
		return false;
	}
	Sleep(6000);

	DeleteFileW(sz_driver.c_str());
	DeleteFileW(sz_mapper.c_str());
	return true;
}

