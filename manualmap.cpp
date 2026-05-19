#include "manualmap.h"

#include <windows.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <iostream>
#include <new>
#include "drv_unified.h"

using namespace std;

static void print_win32_failure(const char* operation, DWORD error)
{
	cout << "[-] " << operation << " failed. GetLastError=" << error;
	if (error == ERROR_ACCESS_DENIED)
	{
		cout << " (Access denied)";
		cout << " -- target denied this remote execution operation";
	}
	else if (error == ERROR_INVALID_HANDLE)
		cout << " (Invalid handle)";
	else if (error == ERROR_NOT_SUPPORTED)
		cout << " (Not supported)";
	cout << endl;
}

class c_messagebox
{
public:

	struct data_t
	{
		uintptr_t messagebox_func; //void*, char*, char*, UINT
		char text[255];
		char caption[255];
	};

	//simulated dllmain
	static int __stdcall dllmain(data_t* data, DWORD reason, void* reserved)
	{
		auto msgbox = reinterpret_cast<int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT)>(data->messagebox_func);
		msgbox(nullptr, data->text, data->caption, MB_OK);
		return 1;
	}
};

class c_loader
{
public:
	struct data_t
	{
		data_t(uintptr_t _base, uintptr_t _image_base, uintptr_t _entry_point, uintptr_t _base_relocation, uintptr_t _import_directory, uintptr_t _loadlib, uintptr_t _get_proc_address, uintptr_t _messagebox_func,
			uintptr_t _rtl_add_function_table, uintptr_t _exception_dir_rva, DWORD _exception_dir_size,
			uintptr_t _tls_dir_rva, DWORD _size_of_image)
		{
			base = _base;
			image_base = _image_base;
			entry_point = _entry_point;
			base_relocation = _base_relocation;
			import_directory = _import_directory;
			loadlib = _loadlib;
			get_proc_address = _get_proc_address;
			messagebox_func = _messagebox_func;
			rtl_add_function_table = _rtl_add_function_table;
			exception_dir_rva = _exception_dir_rva;
			exception_dir_size = _exception_dir_size;
			tls_dir_rva = _tls_dir_rva;
			size_of_image = _size_of_image;
		}

		uintptr_t base;
		uintptr_t image_base;
		uintptr_t entry_point;
		uintptr_t base_relocation;
		uintptr_t import_directory;
		uintptr_t loadlib;
		uintptr_t get_proc_address;
		uintptr_t messagebox_func;
		uintptr_t rtl_add_function_table;
		uintptr_t exception_dir_rva;
		DWORD     exception_dir_size;
		uintptr_t tls_dir_rva;
		DWORD     size_of_image;
	};

	static int __stdcall loader_code(data_t* data, DWORD reason, void* reserved)
	{
		uintptr_t base = data->base;
		uintptr_t delta = base - data->image_base;

		IMAGE_BASE_RELOCATION* base_relocation = (IMAGE_BASE_RELOCATION*)(base + data->base_relocation);
		IMAGE_IMPORT_DESCRIPTOR* import_directory = (IMAGE_IMPORT_DESCRIPTOR*)(base + data->import_directory);

		auto dll_main = reinterpret_cast<int(__stdcall*)(HMODULE, DWORD, void*)>(base + data->entry_point);
		auto loadlib = reinterpret_cast<HMODULE(__stdcall*)(LPCSTR)>(data->loadlib);
		auto get_proc_address = reinterpret_cast<FARPROC(__stdcall*)(HMODULE, LPCSTR)>(data->get_proc_address);
		auto msgbox = reinterpret_cast<int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT)>(data->messagebox_func);

		//relocate the image
		while (base_relocation->SizeOfBlock > 0)
		{
			uintptr_t start_address = base + base_relocation->VirtualAddress;

			//relocations in this block
			size_t reloc_count = (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

			for (size_t i = 0; i < reloc_count; i++)
			{
				uint16_t reloc_data = *(uint16_t*)(uintptr_t(base_relocation) + sizeof(IMAGE_BASE_RELOCATION) + sizeof(uint16_t) * i);
				uint16_t reloc_type = reloc_data & 0xF000;
				uint16_t reloc_offset = reloc_data & 0x0FFF;

				//this could be wrong
				if (reloc_type == 0xA000)
					*(uintptr_t*)(start_address + reloc_offset) += delta;
			}

			base_relocation = (IMAGE_BASE_RELOCATION*)(uintptr_t(base_relocation) + base_relocation->SizeOfBlock);
		}

		//resolve imports
		while (import_directory->Characteristics)
		{
			//get thunk data
			IMAGE_THUNK_DATA* original_first_thunk = (IMAGE_THUNK_DATA*)(base + import_directory->OriginalFirstThunk);
			IMAGE_THUNK_DATA* first_thunk = (IMAGE_THUNK_DATA*)(base + import_directory->FirstThunk);

			//load the requested module with loadlibrary :>
			HMODULE import_module = loadlib((LPCSTR)(base + import_directory->Name));

			if (!import_module)
				msgbox(nullptr, (LPCSTR)(base + import_directory->Name), "LIB", MB_OK);

			//bb got dat func in da thunk
			while (original_first_thunk->u1.AddressOfData)
			{
				if (original_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					//resolve import func by ordinal (REALLY UNCOMMON)
					LPCSTR func_name = (LPCSTR)(original_first_thunk->u1.Ordinal & 0xFFFF);
					uintptr_t func_addr = (uintptr_t)get_proc_address(import_module, func_name);

					if (!func_addr)
						msgbox(nullptr, (LPCSTR)(base + import_directory->Name), "ORD", MB_OK);

					first_thunk->u1.Function = func_addr;
				}
				else
				{
					//resolve import func by name
					IMAGE_IMPORT_BY_NAME* import_by_name = (IMAGE_IMPORT_BY_NAME*)(base + original_first_thunk->u1.AddressOfData);
					LPCSTR func_name = (LPCSTR)import_by_name->Name;
					uintptr_t func_addr = (uintptr_t)get_proc_address(import_module, func_name);

					if (!func_addr)
						msgbox(nullptr, (LPCSTR)(base + import_directory->Name), "IBM", MB_OK);

					first_thunk->u1.Function = func_addr;
				}

				original_first_thunk++;
				first_thunk++;
			}

			import_directory++;
		}

#ifdef _WIN64
		//register exception handlers (critical for x64 SEH - prevents crashes after DllMain)
		if (data->rtl_add_function_table && data->exception_dir_rva && data->exception_dir_size)
		{
			auto rtl_add_func_table = reinterpret_cast<BOOLEAN(__stdcall*)(PRUNTIME_FUNCTION, DWORD, DWORD64)>(data->rtl_add_function_table);
			PRUNTIME_FUNCTION func_table = (PRUNTIME_FUNCTION)(base + data->exception_dir_rva);
			DWORD entry_count = data->exception_dir_size / sizeof(RUNTIME_FUNCTION);
			rtl_add_func_table(func_table, entry_count, base);
		}
#endif

		//invoke TLS callbacks (if present)
		if (data->tls_dir_rva)
		{
			IMAGE_TLS_DIRECTORY* tls_dir = (IMAGE_TLS_DIRECTORY*)(base + data->tls_dir_rva);
			PIMAGE_TLS_CALLBACK* tls_callback = (PIMAGE_TLS_CALLBACK*)tls_dir->AddressOfCallBacks;
			if (tls_callback)
			{
				while (*tls_callback)
				{
					(*tls_callback)((PVOID)base, DLL_PROCESS_ATTACH, nullptr);
					tls_callback++;
				}
			}
		}

		//call entry of module
		dll_main((HMODULE)base, DLL_PROCESS_ATTACH, nullptr);
		return 1;
	}
};

int manual_map::find_hijack_thread(int pid)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 te32{ };
	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(snapshot, &te32))
	{
		CloseHandle(snapshot);
		return 0;
	}

	do
	{
		if (te32.th32OwnerProcessID == pid)
		{
			CloseHandle(snapshot);
			return te32.th32ThreadID;
		}
	} while (Thread32Next(snapshot, &te32));

	CloseHandle(snapshot);
	return 0;
}

bool manual_map::execute_shellcode(int pid, void* process_handle, void* shellcode_address)
{
	UNREFERENCED_PARAMETER(pid);

	HANDLE process = (HANDLE)process_handle;
	if (!process || !shellcode_address)
		return false;

	// Create a remote thread to execute the shellcode instead of hijacking an existing thread
	HANDLE thread = CreateRemoteThread(process, nullptr, 0, (LPTHREAD_START_ROUTINE)shellcode_address, nullptr, 0, nullptr);
	if (!thread)
	{
		printf("couldnt create remote thread\n");
		return false;
	}

	// Wait for the shellcode to finish
	DWORD waitResult = WaitForSingleObject(thread, 10000);
	if (waitResult != WAIT_OBJECT_0)
	{
		printf("remote shellcode wait failed or timed out. wait_result=%lu GetLastError=%lu\n", waitResult, GetLastError());
		CloseHandle(thread);
		return false;
	}

	// Clean up
	CloseHandle(thread);

	return true;
}

bool manual_map::hijack_call_dllmain(int pid, void* process_handle, uintptr_t func_address, uintptr_t argument)
{
	UNREFERENCED_PARAMETER(pid);

	HANDLE process = (HANDLE)process_handle;
	if (!process || !func_address)
		return false;

	//generate shellcode
#ifdef _WIN64
	uint8_t shellcode[]
	{
		0x9C, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,   // push     push registers
		0x48, 0x83, 0xEC, 0x20,                                                         // sub      rsp 0x20
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                     // movabs   rcx 0x0000000000000000 
		0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,                                       // mov      rdx 0x1
		0x4D, 0x31, 0xC0,                                                               // xor      r8 r8
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                     // movabs   rax 0x0000000000000000
		0xFF, 0xD0,                                                                     // call     rax
		0x48, 0x83, 0xC4, 0x20,                                                         // add      rsp 0x20
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B, 0x58, 0x9D,   // pop      pop registers
		0xC3                                                                            // ret
	};

	*(uintptr_t*)(shellcode + 19) = uintptr_t(argument);
	*(uintptr_t*)(shellcode + 39) = uintptr_t(func_address);
#else
	uint8_t shellcode[]
	{
		0x9C,                           // pushfd   push flags
		0x60,                           // pushad   push registers
		0x68, 0x00, 0x00, 0x00, 0x00,   // push     nullptr (0x0)
		0x68, 0x01, 0x00, 0x00, 0x00,   // push     DLL_PROCESS_ATTACH (0x1)
		0x68, 0x00, 0x00, 0x00, 0x00,   // push     0x00000000
		0xB8, 0x00, 0x00, 0x00, 0x00,   // mov      eax 0x00000000
		0xFF, 0xD0,	                    // call     eax
		0x61,                           // popad    pop registers	
		0x9D,                           // popfd    pop flags
		0xC3                            // ret
	};

	*(uintptr_t*)(shellcode + 13) = uintptr_t(argument);
	*(uintptr_t*)(shellcode + 18) = uintptr_t(func_address);
#endif

	//write shellcode
	void* shellcode_address = VirtualAllocEx(process, nullptr, sizeof(shellcode) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(process, shellcode_address, shellcode, sizeof(shellcode), nullptr);

	//execute shellcode
	return execute_shellcode(pid, process, shellcode_address);
}

bool manual_map::hijack_loadlib(int pid, void* process_handle, const char* dll)
{
	HANDLE process = (HANDLE)process_handle;

	//write library path
	void* lib_path_address = VirtualAllocEx(process, nullptr, strlen(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(process, lib_path_address, dll, strlen(dll) + 1, nullptr);

	//get loadlib address
	void* loadlib_address = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

#ifdef _WIN64
	//generate shellcode
	uint8_t shellcode[]
	{
		0x9C, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push     push registers
		0x48, 0x83, 0xEC, 0x28,                                                       // sub      rsp, 0x28
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // movabs   rcx, 0x0000000000000000
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // movabs   rax, 0x0000000000000000
		0xFF, 0xD0,                                                                   // call     rax
		0x48, 0x83, 0xC4, 0x28,                                                       // add      rsp, 0x28
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B, 0x58, 0x9D, // pop      pop registers
		0xC3                                                                          // ret
	};

	*(uintptr_t*)(shellcode + 19) = uintptr_t(lib_path_address);
	*(uintptr_t*)(shellcode + 29) = uintptr_t(loadlib_address);
#else
	uint8_t shellcode[]
	{
		0x9C, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, // push     push registers
		0x48, 0x83, 0xEC, 0x28,                                                       // sub      rsp, 0x28
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // movabs   rcx, 0x0000000000000000
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                   // movabs   rax, 0x0000000000000000
		0xFF, 0xD0,                                                                   // call     rax
		0x48, 0x83, 0xC4, 0x28,                                                       // add      rsp, 0x28
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B, 0x58, 0x9D, // pop      pop registers
		0xC3                                                                          // ret
	};
#endif

	//write shellcode
	void* shellcode_address = VirtualAllocEx(process, nullptr, sizeof(shellcode) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(process, shellcode_address, shellcode, sizeof(shellcode), nullptr);

	//execute shellcode
	return execute_shellcode(pid, process, shellcode_address);
}

bool manual_map::inject_from_memory(int pid, uint8_t* dll, bool register_peb, const char* dll_path)
{
	cout << "[+] Starting injection from memory (Kernel-assisted ManualMap)" << endl;

	if (pid <= 0 || !dll)
	{
		cout << "[-] Invalid manual map input." << endl;
		return false;
	}

	if (!drv::is_loaded())
	{
		cout << "[-] Selected driver backend is not connected." << endl;
		return false;
	}

	//attach kernel driver to target
	drv::attach(pid);

	//get headers
	IMAGE_DOS_HEADER* dos_header = (PIMAGE_DOS_HEADER)dll;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew <= 0)
	{
		cout << "[-] Invalid DOS header." << endl;
		return false;
	}

	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(dll + dos_header->e_lfanew);
	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		cout << "[-] Invalid NT header." << endl;
		return false;
	}

	IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)((uintptr_t)nt_header + sizeof(IMAGE_NT_HEADERS));

	size_t    size_of_image = nt_header->OptionalHeader.SizeOfImage;
	size_t    size_of_headers = nt_header->OptionalHeader.SizeOfHeaders;
	uintptr_t image_base = nt_header->OptionalHeader.ImageBase;
	uintptr_t entry_point = nt_header->OptionalHeader.AddressOfEntryPoint;
	size_t    section_count = nt_header->FileHeader.NumberOfSections;
	if (size_of_image == 0 || size_of_headers == 0 || section_count == 0 ||
		size_of_image > MAXDWORD || size_of_headers > size_of_image)
	{
		cout << "[-] Invalid image dimensions." << endl;
		return false;
	}

	//allocate memory in target via kernel driver
	void* module_address = drv::alloc((DWORD)size_of_image, PAGE_EXECUTE_READWRITE);
	if (!module_address)
	{
		cout << "[-] Kernel alloc failed. Is the driver loaded?" << endl;
		return false;
	}
	cout << "[+] Allocated via kernel at: 0x" << hex << (uintptr_t)module_address << endl;

	//create a local copy of the image to fix up
	uint8_t* local_image = new (std::nothrow) uint8_t[size_of_image];
	if (!local_image)
	{
		cout << "[-] Local image allocation failed." << endl;
		drv::free_mem(module_address);
		return false;
	}
	memset(local_image, 0, size_of_image);

	//copy headers
	memcpy(local_image, dll, size_of_headers);

	//copy sections
	for (size_t i = 0; i < section_count; i++)
	{
		if (section_header[i].SizeOfRawData > 0)
		{
			memcpy(local_image + section_header[i].VirtualAddress,
				dll + section_header[i].PointerToRawData,
				section_header[i].SizeOfRawData);
		}
	}
	cout << "[+] Sections copied." << endl;

	//fix relocations on the local copy
	uintptr_t delta = (uintptr_t)module_address - image_base;
	if (delta != 0)
	{
		DWORD reloc_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		DWORD reloc_size = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if (reloc_rva && reloc_size)
		{
			IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(local_image + reloc_rva);
			uintptr_t reloc_end = (uintptr_t)reloc + reloc_size;

			while ((uintptr_t)reloc < reloc_end && reloc->SizeOfBlock > 0)
			{
				DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
				uint16_t* entries = (uint16_t*)((uintptr_t)reloc + sizeof(IMAGE_BASE_RELOCATION));

				for (DWORD i = 0; i < count; i++)
				{
					uint16_t type = entries[i] >> 12;
					uint16_t offset = entries[i] & 0x0FFF;

					if (type == IMAGE_REL_BASED_DIR64)
						*(uintptr_t*)(local_image + reloc->VirtualAddress + offset) += delta;
					else if (type == IMAGE_REL_BASED_HIGHLOW)
						*(DWORD*)(local_image + reloc->VirtualAddress + offset) += (DWORD)delta;
				}

				reloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)reloc + reloc->SizeOfBlock);
			}
		}
	}
	cout << "[+] Relocations applied." << endl;

	//resolve imports on the local copy
	DWORD import_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (import_rva)
	{
		IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(local_image + import_rva);
		bool importFailure = false;

		while (import_desc->Characteristics && !importFailure)
		{
			char* module_name = (char*)(local_image + import_desc->Name);
			HMODULE hMod = LoadLibraryA(module_name);

			if (!hMod)
			{
				cout << "[-] Failed to load dependency: " << module_name << endl;
				importFailure = true;
				break;
			}

			DWORD thunkRva = import_desc->OriginalFirstThunk ? import_desc->OriginalFirstThunk : import_desc->FirstThunk;
			IMAGE_THUNK_DATA* orig_thunk = (IMAGE_THUNK_DATA*)(local_image + thunkRva);
			IMAGE_THUNK_DATA* first_thunk = (IMAGE_THUNK_DATA*)(local_image + import_desc->FirstThunk);

			while (orig_thunk->u1.AddressOfData)
			{
				FARPROC proc = nullptr;
				if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					proc = ::GetProcAddress(hMod, (LPCSTR)(orig_thunk->u1.Ordinal & 0xFFFF));
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(local_image + orig_thunk->u1.AddressOfData);
					proc = ::GetProcAddress(hMod, ibn->Name);
				}
				if (!proc)
				{
					cout << "[-] Failed to resolve import from: " << module_name << endl;
					importFailure = true;
					break;
				}

				first_thunk->u1.Function = (uintptr_t)proc;

				orig_thunk++;
				first_thunk++;
			}

			import_desc++;
		}
		if (importFailure)
		{
			delete[] local_image;
			drv::free_mem(module_address);
			return false;
		}
	}
	cout << "[+] Imports resolved." << endl;

	//write the fully fixed-up image to the target via kernel driver
	if (!drv::write(module_address, local_image, (DWORD)size_of_image))
	{
		cout << "[-] Failed to write image to target via driver." << endl;
		delete[] local_image;
		drv::free_mem(module_address);
		return false;
	}
	cout << "[+] Image written to target via kernel." << endl;

	delete[] local_image;

#ifdef _WIN64
	//register exception tables via a small shellcode (RtlAddFunctionTable)
	DWORD exc_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	DWORD exc_size = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	if (exc_rva && exc_size)
	{
		uintptr_t func_table_addr = (uintptr_t)module_address + exc_rva;
		DWORD entry_count = exc_size / sizeof(RUNTIME_FUNCTION);
		uintptr_t rtl_add = (uintptr_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "RtlAddFunctionTable");
		if (!rtl_add)
		{
			cout << "[-] RtlAddFunctionTable was not available." << endl;
		}
		else
		{

			// Shellcode: sub rsp,0x28 / mov rcx,[func_table] / mov edx,[count] / mov r8,[base] / mov rax,[RtlAddFunctionTable] / call rax / add rsp,0x28 / ret
			uint8_t sc[] = {
				0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
				0x48, 0xB9, 0,0,0,0,0,0,0,0,                               // mov rcx, func_table_addr
				0xBA, 0,0,0,0,                                              // mov edx, entry_count
				0x49, 0xB8, 0,0,0,0,0,0,0,0,                               // mov r8, module_address (base)
				0x48, 0xB8, 0,0,0,0,0,0,0,0,                               // mov rax, RtlAddFunctionTable
				0xFF, 0xD0,                                                 // call rax
				0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
				0xC3                                                        // ret
			};
			*(uintptr_t*)(sc + 6) = func_table_addr;
			*(DWORD*)(sc + 15) = entry_count;
			*(uintptr_t*)(sc + 21) = (uintptr_t)module_address;
			*(uintptr_t*)(sc + 31) = rtl_add;

			void* sc_mem = drv::alloc(sizeof(sc), PAGE_EXECUTE_READWRITE);
			if (sc_mem && drv::write(sc_mem, sc, sizeof(sc)))
			{
				bool exceptionTableThreadRan = false;
				HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | SYNCHRONIZE, FALSE, pid);
				if (hProc) {
					SetLastError(ERROR_SUCCESS);
					HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)sc_mem, nullptr, 0, nullptr);
					if (hThread) {
						exceptionTableThreadRan = WaitForSingleObject(hThread, 5000) == WAIT_OBJECT_0;
						CloseHandle(hThread);
					}
					else { print_win32_failure("CreateRemoteThread(RtlAddFunctionTable)", GetLastError()); }
					CloseHandle(hProc);
				}
				else { print_win32_failure("OpenProcess(RtlAddFunctionTable)", GetLastError()); }
				drv::free_mem(sc_mem);
				if (exceptionTableThreadRan)
					cout << "[+] Exception tables registered." << endl;
				else
					cout << "[!] Exception table registration did not confirm completion." << endl;
			}
			else
			{
				if (sc_mem) drv::free_mem(sc_mem);
				cout << "[-] Exception table shellcode staging failed." << endl;
			}
		}
	}
#endif

	//initialize TLS if the DLL has a TLS directory
	DWORD tls_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	DWORD tls_size = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	if (tls_rva && tls_size)
	{
		cout << "[+] TLS directory found, allocating TLS slot..." << endl;
		bool tlsSetupOk = false;
		uintptr_t tls_alloc_addr = (uintptr_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "TlsAlloc");

		// Shellcode: call TlsAlloc, store result in allocated memory, return
		// sub rsp,0x28 / mov rax,[TlsAlloc] / call rax / mov rcx,[output_addr] / mov [rcx],eax / add rsp,0x28 / ret
		void* tls_result_mem = drv::alloc(sizeof(DWORD), PAGE_READWRITE);
		if (!tls_alloc_addr || !tls_result_mem)
		{
			cout << "[-] TLS setup prerequisites failed." << endl;
			if (tls_result_mem) drv::free_mem(tls_result_mem);
		}
		else
		{
			DWORD tls_initial_value = TLS_OUT_OF_INDEXES;
			if (!drv::write(tls_result_mem, &tls_initial_value, sizeof(tls_initial_value)))
			{
				cout << "[-] Failed to initialize TLS result buffer." << endl;
				drv::free_mem(tls_result_mem);
				return false;
			}

			uint8_t tls_sc[] = {
				0x48, 0x83, 0xEC, 0x28,                 // [0-3]   sub rsp, 0x28
				0x48, 0xB8, 0,0,0,0,0,0,0,0,           // [4-13]  mov rax, TlsAlloc
				0xFF, 0xD0,                             // [14-15] call rax
				0x48, 0xB9, 0,0,0,0,0,0,0,0,           // [16-25] mov rcx, output_addr
				0x89, 0x01,                             // [26-27] mov [rcx], eax
				0x48, 0x83, 0xC4, 0x28,                 // [28-31] add rsp, 0x28
				0xC3                                    // [32]    ret
			};
			*(uintptr_t*)(tls_sc + 6) = tls_alloc_addr;
			*(uintptr_t*)(tls_sc + 18) = (uintptr_t)tls_result_mem;

			void* tls_sc_mem = drv::alloc(sizeof(tls_sc), PAGE_EXECUTE_READWRITE);
			bool tlsThreadRan = false;
			if (tls_sc_mem && drv::write(tls_sc_mem, tls_sc, sizeof(tls_sc)))
			{
				HANDLE hProc2 = OpenProcess(PROCESS_CREATE_THREAD | SYNCHRONIZE, FALSE, pid);
				if (hProc2) {
					SetLastError(ERROR_SUCCESS);
					HANDLE hTlsThread = CreateRemoteThread(hProc2, nullptr, 0, (LPTHREAD_START_ROUTINE)tls_sc_mem, nullptr, 0, nullptr);
					if (hTlsThread) {
						const DWORD waitResult = WaitForSingleObject(hTlsThread, 5000);
						tlsThreadRan = waitResult == WAIT_OBJECT_0;
						if (!tlsThreadRan)
							cout << "[-] TlsAlloc thread wait failed or timed out. wait_result=" << waitResult << endl;
						CloseHandle(hTlsThread);
					}
					else { print_win32_failure("CreateRemoteThread(TlsAlloc)", GetLastError()); }
					CloseHandle(hProc2);
				}
				else { print_win32_failure("OpenProcess(TlsAlloc)", GetLastError()); }
			}
			else
			{
				cout << "[-] TLS shellcode staging failed." << endl;
			}
			if (tls_sc_mem) drv::free_mem(tls_sc_mem);

			if (tlsThreadRan)
			{
				// Read the allocated TLS index via kernel
				DWORD tls_index = TLS_OUT_OF_INDEXES;
				const bool tls_read = drv::read(tls_result_mem, &tls_index, sizeof(DWORD));

				if (tls_read && tls_index != TLS_OUT_OF_INDEXES)
				{
					// Read the TLS directory from the mapped image to get AddressOfIndex
					IMAGE_TLS_DIRECTORY64 tls_dir = { 0 };
					if (drv::read((PBYTE)module_address + tls_rva, &tls_dir, sizeof(tls_dir)) &&
						drv::write((PVOID)tls_dir.AddressOfIndex, &tls_index, sizeof(DWORD)))
					{
						tlsSetupOk = true;
						cout << "[+] TLS index allocated: " << dec << tls_index << endl;
					}
					else
					{
						cout << "[-] TLS directory update failed." << endl;
					}
				}
				else
				{
					cout << "[-] TlsAlloc failed or result was not readable." << endl;
				}
			}
			else
			{
				cout << "[-] TLS setup execution did not run; refusing to call DllMain with TLS uninitialized." << endl;
			}

			drv::free_mem(tls_result_mem);
		}

		if (!tlsSetupOk)
			return false;
	}

	//call DllMain via CreateRemoteThread (entry point = _DllMainCRTStartup)
	uintptr_t ep_addr = (uintptr_t)module_address + entry_point;

	// Shellcode: sub rsp,0x28 / mov rcx,[base] / mov edx,1 / xor r8,r8 / mov rax,[ep] / call rax / add rsp,0x28 / ret
	uint8_t ep_sc[] = {
		0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
		0x48, 0xB9, 0,0,0,0,0,0,0,0,                               // mov rcx, module_address (hModule)
		0xBA, 0x01, 0x00, 0x00, 0x00,                               // mov edx, DLL_PROCESS_ATTACH
		0x4D, 0x31, 0xC0,                                           // xor r8, r8 (lpReserved = NULL)
		0x48, 0xB8, 0,0,0,0,0,0,0,0,                               // mov rax, entry_point_addr
		0xFF, 0xD0,                                                 // call rax
		0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
		0xC3                                                        // ret
	};
	*(uintptr_t*)(ep_sc + 6) = (uintptr_t)module_address;
	*(uintptr_t*)(ep_sc + 24) = ep_addr;

	void* ep_mem = drv::alloc(sizeof(ep_sc), PAGE_EXECUTE_READWRITE);
	if (!ep_mem || !drv::write(ep_mem, ep_sc, sizeof(ep_sc)))
	{
		cout << "[-] Entry point shellcode staging failed." << endl;
		if (ep_mem) drv::free_mem(ep_mem);
		return false;
	}

	cout << "[+] Calling DllMain..." << endl;
	bool dllMainCalled = false;
	HANDLE hProc3 = OpenProcess(PROCESS_CREATE_THREAD | SYNCHRONIZE, FALSE, pid);
	if (hProc3) {
		SetLastError(ERROR_SUCCESS);
		HANDLE hEpThread = CreateRemoteThread(hProc3, nullptr, 0, (LPTHREAD_START_ROUTINE)ep_mem, nullptr, 0, nullptr);
		if (hEpThread) {
			DWORD waitResult = WaitForSingleObject(hEpThread, 10000);
			dllMainCalled = waitResult == WAIT_OBJECT_0;
			if (!dllMainCalled)
				cout << "[-] DllMain thread wait failed or timed out. wait_result=" << waitResult << endl;
			CloseHandle(hEpThread);
		}
		else {
			print_win32_failure("CreateRemoteThread(DllMain)", GetLastError());
		}
		CloseHandle(hProc3);
	}
	else {
		print_win32_failure("OpenProcess(DllMain)", GetLastError());
	}
	drv::free_mem(ep_mem);
	if (!dllMainCalled)
		return false;

	cout << "[+] DllMain returned." << endl;

	//register module in PEB if requested
	if (register_peb && dll_path)
	{
		cout << "[+] Registering module in PEB..." << endl;
		if (register_in_peb(pid, module_address, (DWORD)size_of_image, entry_point, dll_path))
			cout << "[+] PEB registration successful." << endl;
		else
			cout << "[-] PEB registration failed." << endl;
	}
	cout << "[+] Manual map injection complete." << endl;
	return true;
}

bool manual_map::inject_from_path(int pid, const char* dll, bool register_peb)
{
	system("CLS");

	cout << "[+] Injection from path" << endl;
	cout << "[+] Opening %s " << dll << endl;

	//printf( "> injecting from path \n" );
	//printf( "> opening: %s \n", dll );

	HANDLE file_handle = CreateFileA(dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (file_handle == INVALID_HANDLE_VALUE)
	{
		cout << "[-] Unable to open target Dll." << endl;

		return false;
	}

	DWORD file_size = GetFileSize(file_handle, nullptr);
	uint8_t* buffer = new uint8_t[file_size];

	cout << "[+] Reading %s " << dll << endl;

	if (!ReadFile(file_handle, buffer, file_size, nullptr, nullptr))
	{
		cout << "[-] Unable to read DLL file." << endl;
		CloseHandle(file_handle);
		delete[] buffer;
		return false;
	}
	CloseHandle(file_handle);

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)buffer; //file start 
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("> does not look like a valid DLL! \n");
		cout << "[-] Invalid DLL" << endl;
		delete[] buffer;
		return false;
	}

	cout << "[+] DLL Loaded" << endl;

	bool injected = inject_from_memory(pid, buffer, register_peb, dll);

	delete[] buffer;
	return injected;
}

bool manual_map::register_in_peb(int pid, void* module_base, DWORD size_of_image, uintptr_t entry_point, const char* dll_path)
{
	// Need a process handle only for NtQueryInformationProcess
	typedef long(__stdcall* fnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
	auto NtQueryInformationProcess = (fnNtQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) return false;

	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (!process) return false;

	struct { PVOID r1; PVOID PebBase; PVOID r2[2]; ULONG_PTR pid; PVOID r3; } pbi;
	ULONG retLen;
	bool ok = (NtQueryInformationProcess(process, 0, &pbi, sizeof(pbi), &retLen) == 0);
	CloseHandle(process);
	if (!ok) return false;

	// All reads/writes below use kernel driver (driver() is already attached)
	PVOID pebLdr;
	if (!drv::read((PBYTE)pbi.PebBase + 0x18, &pebLdr, sizeof(pebLdr))) return false;

	PBYTE loadOrderHead = (PBYTE)pebLdr + 0x10;
	LIST_ENTRY loadOrderLinks;
	if (!drv::read(loadOrderHead, &loadOrderLinks, sizeof(loadOrderLinks))) return false;

	PBYTE memOrderHead = (PBYTE)pebLdr + 0x20;
	LIST_ENTRY memOrderLinks;
	if (!drv::read(memOrderHead, &memOrderLinks, sizeof(memOrderLinks))) return false;

	// Prepare DLL name strings
	std::string pathStr(dll_path);
	size_t slash = pathStr.find_last_of("\\/");
	std::string baseName = (slash != std::string::npos) ? pathStr.substr(slash + 1) : pathStr;

	int wFullLen = MultiByteToWideChar(CP_ACP, 0, dll_path, -1, nullptr, 0);
	int wBaseLen = MultiByteToWideChar(CP_ACP, 0, baseName.c_str(), -1, nullptr, 0);
	if (wFullLen <= 0 || wBaseLen <= 0)
		return false;

	std::wstring wFull(wFullLen, 0);
	std::wstring wBase(wBaseLen, 0);
	if (!MultiByteToWideChar(CP_ACP, 0, dll_path, -1, &wFull[0], wFullLen) ||
		!MultiByteToWideChar(CP_ACP, 0, baseName.c_str(), -1, &wBase[0], wBaseLen))
		return false;

	// Allocate via kernel driver
	size_t strSpace = (wFullLen + wBaseLen + 2) * sizeof(wchar_t);
	PBYTE entryMem = (PBYTE)drv::alloc((DWORD)(0x120 + strSpace), PAGE_READWRITE);
	if (!entryMem) return false;

	PBYTE fullNameBuf = entryMem + 0x120;
	PBYTE baseNameBuf = fullNameBuf + wFullLen * sizeof(wchar_t);

	// Write name strings via kernel
	if (!drv::write(fullNameBuf, (PVOID)wFull.c_str(), wFullLen * sizeof(wchar_t)) ||
		!drv::write(baseNameBuf, (PVOID)wBase.c_str(), wBaseLen * sizeof(wchar_t)))
	{
		drv::free_mem(entryMem);
		return false;
	}

	// Build LDR_DATA_TABLE_ENTRY
	BYTE entry[0x120] = { 0 };
	*(PVOID*)(entry + 0x00) = loadOrderHead;
	*(PVOID*)(entry + 0x08) = loadOrderLinks.Blink;
	*(PVOID*)(entry + 0x10) = memOrderHead;
	*(PVOID*)(entry + 0x18) = memOrderLinks.Blink;
	*(PVOID*)(entry + 0x20) = entryMem + 0x20;
	*(PVOID*)(entry + 0x28) = entryMem + 0x20;
	*(PVOID*)(entry + 0x30) = module_base;
	*(uintptr_t*)(entry + 0x38) = (uintptr_t)module_base + entry_point;
	*(ULONG*)(entry + 0x40) = size_of_image;
	*(USHORT*)(entry + 0x48) = (USHORT)((wFullLen - 1) * sizeof(wchar_t));
	*(USHORT*)(entry + 0x4A) = (USHORT)(wFullLen * sizeof(wchar_t));
	*(PVOID*)(entry + 0x50) = fullNameBuf;
	*(USHORT*)(entry + 0x58) = (USHORT)((wBaseLen - 1) * sizeof(wchar_t));
	*(USHORT*)(entry + 0x5A) = (USHORT)(wBaseLen * sizeof(wchar_t));
	*(PVOID*)(entry + 0x60) = baseNameBuf;
	*(ULONG*)(entry + 0x68) = 0x000C4004;
	*(USHORT*)(entry + 0x6C) = 1;

	// Write entry via kernel
	if (!drv::write(entryMem, entry, 0x120))
	{
		drv::free_mem(entryMem);
		return false;
	}

	// Link into lists via kernel
	PVOID newLoadOrderEntry = entryMem + 0x00;
	if (!drv::write((PBYTE)loadOrderLinks.Blink + 0x00, &newLoadOrderEntry, sizeof(PVOID)) ||
		!drv::write(loadOrderHead + 0x08, &newLoadOrderEntry, sizeof(PVOID)))
	{
		drv::free_mem(entryMem);
		return false;
	}

	PVOID newMemOrderEntry = entryMem + 0x10;
	if (!drv::write((PBYTE)memOrderLinks.Blink + 0x00, &newMemOrderEntry, sizeof(PVOID)) ||
		!drv::write(memOrderHead + 0x08, &newMemOrderEntry, sizeof(PVOID)))
	{
		drv::free_mem(entryMem);
		return false;
	}

	return true;
}

bool manual_map::hijack_messagebox_test(int pid)
{
	printf("> messagebox test \n");

	HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
	if (!process)
	{
		printf("> unable to open process! \n");
		return false;
	}

	c_messagebox::data_t msgbox_data;
	msgbox_data.messagebox_func = uintptr_t(GetProcAddress(GetModuleHandleA("User32.dll"), "MessageBoxA"));
	if (!msgbox_data.messagebox_func)
	{
		printf("> unable to resolve MessageBoxA! \n");
		CloseHandle(process);
		return false;
	}
	strncpy_s(msgbox_data.text, 9, "TEST_MSG", 9);
	strncpy_s(msgbox_data.caption, 7, "HELLO", 7);

	//write loader data
	void* loader_data_address = VirtualAllocEx(process, nullptr, sizeof(msgbox_data) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!loader_data_address ||
		!WriteProcessMemory(process, loader_data_address, &msgbox_data, sizeof(msgbox_data), nullptr))
	{
		printf("> unable to write messagebox data! \n");
		if (loader_data_address) VirtualFreeEx(process, loader_data_address, 0, MEM_RELEASE);
		CloseHandle(process);
		return false;
	}

	//write function
	void* dllmain_address = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!dllmain_address ||
		!WriteProcessMemory(process, dllmain_address, c_messagebox::dllmain, 0x1000, nullptr))
	{
		printf("> unable to write messagebox code! \n");
		if (dllmain_address) VirtualFreeEx(process, dllmain_address, 0, MEM_RELEASE);
		VirtualFreeEx(process, loader_data_address, 0, MEM_RELEASE);
		CloseHandle(process);
		return false;
	}

	bool called = hijack_call_dllmain(pid, process, uintptr_t(dllmain_address), uintptr_t(loader_data_address));

	VirtualFreeEx(process, dllmain_address, 0, MEM_RELEASE);
	VirtualFreeEx(process, loader_data_address, 0, MEM_RELEASE);
	CloseHandle(process);

	getchar();

	return called;
}
