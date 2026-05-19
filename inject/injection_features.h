#pragma once
#include "utils.h"
#include "../struct.h"
#include "../bytes.h"
#include "../api/xor.h"
#include "../drv_unified.h"
#include "../define/stdafx.h"


uintptr_t call_remote_load_library(DWORD thread_id, LPCSTR dll_name)
{
	HMODULE nt_dll = LoadLibraryW(xor_w(L"ntdll.dll"));
	if (!nt_dll)
	{
		printf(xor_a("[-] LoadLibraryW(ntdll.dll) failed. GetLastError=%lu\n"), GetLastError());
		return 0;
	}

	PVOID alloc_shell_code = drv::alloc(4096, PAGE_EXECUTE_READWRITE);
	if (!alloc_shell_code)
	{
		printf(xor_a("[-] Driver allocation for hook shellcode failed.\n"));
		FreeLibrary(nt_dll);
		return 0;
	}

	DWORD shell_size = sizeof(remote_load_library) + sizeof(load_library_struct);
	PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!alloc_local)
	{
		printf(xor_a("[-] Local shellcode staging allocation failed. GetLastError=%lu\n"), GetLastError());
		drv::free_mem(alloc_shell_code);
		FreeLibrary(nt_dll);
		return 0;
	}

	
	RtlCopyMemory(alloc_local, &remote_load_library, sizeof(remote_load_library));
	uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_load_library);
	*(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
	load_library_struct* ll_data = (load_library_struct*)((uintptr_t)alloc_local + sizeof(remote_load_library));
	ll_data->fn_load_library_a = (uintptr_t)LoadLibraryA;
	if (strcpy_s(ll_data->module_name, 260, dll_name) != 0)
	{
		printf(xor_a("[-] DLL path is too long for the hook payload buffer.\n"));
		drv::free_mem(alloc_shell_code);
		VirtualFree(alloc_local, 0, MEM_RELEASE);
		FreeLibrary(nt_dll);
		return 0;
	}
	

	
	if (!drv::write(alloc_shell_code, alloc_local, shell_size))
	{
		printf(xor_a("[-] Driver write for hook shellcode failed.\n"));
		drv::free_mem(alloc_shell_code);
		VirtualFree(alloc_local, 0, MEM_RELEASE);
		FreeLibrary(nt_dll);
		return 0;
	}

	HHOOK h_hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);
	if (!h_hook)
	{
		printf(xor_a("[-] SetWindowsHookEx failed. GetLastError=%lu\n"), GetLastError());
		drv::free_mem(alloc_shell_code);
		VirtualFree(alloc_local, 0, MEM_RELEASE);
		FreeLibrary(nt_dll);
		return 0;
	}


	
	DWORD wait_attempts = 0;
	while (ll_data->status != 2 && wait_attempts++ < 500)
	{
		if (!PostThreadMessage(thread_id, WM_NULL, 0, 0))
		{
			printf(xor_a("[-] PostThreadMessage failed. GetLastError=%lu\n"), GetLastError());
			break;
		}
		if (!drv::read((PVOID)shell_data, (PVOID)ll_data, sizeof(load_library_struct)))
		{
			printf(xor_a("[-] Driver read for hook status failed.\n"));
			break;
		}
		Sleep(10);
	} uintptr_t mod_base = ll_data->status == 2 ? ll_data->module_base : 0;
	if (!mod_base)
	{
		printf(xor_a("[-] Hook payload did not report success. status=%d attempts=%lu\n"), ll_data->status, wait_attempts);
		if (ll_data->status == 0)
			printf(xor_a("[-] Hook status 0 means the callback was never observed running on the selected thread.\n"));
		else if (ll_data->status == 1)
			printf(xor_a("[-] Hook status 1 means the callback started but did not finish LoadLibraryA.\n"));
	}
	

	
	UnhookWindowsHookEx(h_hook);
	drv::free_mem(alloc_shell_code);
	VirtualFree(alloc_local, 0, MEM_RELEASE);
	FreeLibrary(nt_dll);
	

	return mod_base;
}



bool call_dll_main(DWORD thread_id, PVOID dll_base, PIMAGE_NT_HEADERS nt_header, bool hide_dll)
{
	UNREFERENCED_PARAMETER(hide_dll);
	
	HMODULE nt_dll = LoadLibraryW(xor_w(L"ntdll.dll"));
	if (!nt_dll)
	{
		printf(xor_a("[-] LoadLibraryW(ntdll.dll) failed. GetLastError=%lu\n"), GetLastError());
		return false;
	}

	PVOID alloc_shell_code = drv::alloc(4096, PAGE_EXECUTE_READWRITE);
	if (!alloc_shell_code)
	{
		printf(xor_a("[-] Driver allocation for DllMain shellcode failed.\n"));
		FreeLibrary(nt_dll);
		return false;
	}

	DWORD shell_size = sizeof(remote_call_dll_main) + sizeof(main_struct);
	PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!alloc_local)
	{
		printf(xor_a("[-] Local DllMain staging allocation failed. GetLastError=%lu\n"), GetLastError());
		drv::free_mem(alloc_shell_code);
		FreeLibrary(nt_dll);
		return false;
	}
	

	
	RtlCopyMemory(alloc_local, &remote_call_dll_main, sizeof(remote_call_dll_main));
	uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_call_dll_main);
	*(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
	main_struct* main_data = (main_struct*)((uintptr_t)alloc_local + sizeof(remote_call_dll_main));
	main_data->dll_base = (HINSTANCE)dll_base;
	main_data->fn_dll_main = ((uintptr_t)dll_base + nt_header->OptionalHeader.AddressOfEntryPoint);
	

	
	if (!drv::write(alloc_shell_code, alloc_local, shell_size))
	{
		printf(xor_a("[-] Driver write for DllMain shellcode failed.\n"));
		drv::free_mem(alloc_shell_code);
		VirtualFree(alloc_local, 0, MEM_RELEASE);
		FreeLibrary(nt_dll);
		return false;
	}

	HHOOK h_hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);
	if (!h_hook)
	{
		printf(xor_a("[-] SetWindowsHookEx for DllMain failed. GetLastError=%lu\n"), GetLastError());
		drv::free_mem(alloc_shell_code);
		VirtualFree(alloc_local, 0, MEM_RELEASE);
		FreeLibrary(nt_dll);
		return false;
	}
	

	
	DWORD wait_attempts = 0;
	while (main_data->status != 2 && wait_attempts++ < 500)
	{
		if (!PostThreadMessage(thread_id, WM_NULL, 0, 0))
		{
			printf(xor_a("[-] PostThreadMessage for DllMain failed. GetLastError=%lu\n"), GetLastError());
			break;
		}
		if (!drv::read((PVOID)shell_data, (PVOID)main_data, sizeof(main_struct)))
		{
			printf(xor_a("[-] Driver read for DllMain status failed.\n"));
			break;
		}
		Sleep(10);
	}
	if (main_data->status != 2)
	{
		printf(xor_a("[-] DllMain hook payload did not report success. status=%d attempts=%lu\n"), main_data->status, wait_attempts);
		if (main_data->status == 0)
			printf(xor_a("[-] DllMain hook status 0 means the callback was never observed running on the selected thread.\n"));
		else if (main_data->status == 1)
			printf(xor_a("[-] DllMain hook status 1 means the callback started but did not finish DllMain.\n"));
	}
	

	
	bool success = main_data->status == 2;
	UnhookWindowsHookEx(h_hook);
	drv::free_mem(alloc_shell_code);
	VirtualFree(alloc_local, 0, MEM_RELEASE);
	FreeLibrary(nt_dll);
	return success;
}

PVOID rva_va(uintptr_t rva, PIMAGE_NT_HEADERS nt_head, PVOID local_image)
{
	PIMAGE_SECTION_HEADER p_first_sect = IMAGE_FIRST_SECTION(nt_head);
	for (PIMAGE_SECTION_HEADER p_section = p_first_sect; p_section < p_first_sect + nt_head->FileHeader.NumberOfSections; p_section++)
		if (rva >= p_section->VirtualAddress && rva < p_section->VirtualAddress + p_section->Misc.VirtualSize)
			return (PUCHAR)local_image + p_section->PointerToRawData + (rva - p_section->VirtualAddress);

	return NULL;
}

uintptr_t resolve_func_addr(LPCSTR modname, LPCSTR modfunc)
{
	HMODULE h_module = LoadLibraryExA(modname, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!h_module)
		return 0;

	uintptr_t func_offset = (uintptr_t)GetProcAddress(h_module, modfunc);
	if (!func_offset)
	{
		FreeLibrary(h_module);
		return 0;
	}

	func_offset -= (uintptr_t)h_module;
	FreeLibrary(h_module);

	return func_offset;
}

BOOL relocate_image(PVOID p_remote_img, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	struct reloc_entry
	{
		ULONG to_rva;
		ULONG size;
		struct
		{
			WORD offset : 12;
			WORD type : 4;
		} item[1];
	};

	uintptr_t delta_offset = (uintptr_t)p_remote_img - nt_head->OptionalHeader.ImageBase;
	if (!delta_offset) return true; else if (!(nt_head->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return false;
	reloc_entry* reloc_ent = (reloc_entry*)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_head, p_local_img);
	uintptr_t reloc_end = (uintptr_t)reloc_ent + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (reloc_ent == nullptr)
		return true;

	while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
	{
		DWORD records_count = (reloc_ent->size - 8) >> 1;
		for (DWORD i = 0; i < records_count; i++)
		{
			WORD fix_type = (reloc_ent->item[i].type);
			WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

			if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64)
			{
				uintptr_t fix_va = (uintptr_t)rva_va(reloc_ent->to_rva, nt_head, p_local_img);

				if (!fix_va)
					fix_va = (uintptr_t)p_local_img;

				*(uintptr_t*)(fix_va + shift_delta) += delta_offset;
			}
		}

		reloc_ent = (reloc_entry*)((LPBYTE)reloc_ent + reloc_ent->size);
	} return true;
}

BOOL resolve_import(DWORD thread_id, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_head, p_local_img);
	if (!nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) return true;

	LPSTR module_name = NULL;
	while ((module_name = (LPSTR)rva_va(import_desc->Name, nt_head, p_local_img)))
	{
		uintptr_t base_image;
		printf(xor_a("[*] Resolving import module: %s\n"), module_name);
		base_image = call_remote_load_library(thread_id, module_name);

		if (!base_image)
		{
			printf(xor_a("[-] Failed to load import module in target: %s\n"), module_name);
			return false;
		}

		PIMAGE_THUNK_DATA ih_data = (PIMAGE_THUNK_DATA)rva_va(import_desc->FirstThunk, nt_head, p_local_img);
		while (ih_data->u1.AddressOfData)
		{
			if (ih_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				uintptr_t function_offset = resolve_func_addr(module_name, (LPCSTR)(ih_data->u1.Ordinal & 0xFFFF));
				if (!function_offset)
					return false;

				ih_data->u1.Function = base_image + function_offset;
			}
			else
			{
				IMAGE_IMPORT_BY_NAME* ibn = (PIMAGE_IMPORT_BY_NAME)rva_va(ih_data->u1.AddressOfData, nt_head, p_local_img);
				if (!ibn)
					return false;

				uintptr_t function_offset = resolve_func_addr(module_name, (LPCSTR)ibn->Name);
				if (!function_offset)
					return false;

				ih_data->u1.Function = base_image + function_offset;
			} ih_data++;
		} import_desc++;
	} return true;
}

bool write_sections(PVOID p_module_base, PVOID local_image, PIMAGE_NT_HEADERS nt_head)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		if (section->SizeOfRawData == 0)
			continue;

		if (!drv::write((PVOID)((uintptr_t)p_module_base + section->VirtualAddress),
			(PVOID)((uintptr_t)local_image + section->PointerToRawData),
			section->SizeOfRawData))
		{
			printf(xor_a("[-] Driver write failed for section %u.\n"), sec_cnt);
			return false;
		}
	}

	return true;
}

bool erase_discardable_sect(PVOID p_module_base, PIMAGE_NT_HEADERS nt_head)
{
	bool ok = true;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		if (section->SizeOfRawData == 0)
			continue;

		if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			PVOID zero_memory = VirtualAlloc(NULL, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!zero_memory)
			{
				ok = false;
				continue;
			}

			if (!drv::write((PVOID)((uintptr_t)p_module_base + section->VirtualAddress), zero_memory, section->SizeOfRawData))
				ok = false;
			VirtualFree(zero_memory, 0, MEM_RELEASE);
		}
	}

	return ok;
}


