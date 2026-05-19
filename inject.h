#include <Windows.h>
#include "inject/utils.h"
#include "api/xor.h"
#include "define/stdafx.h"
#include "drv_unified.h"
#include "inject/injection_features.h"


void inject(LPCSTR window_class_name, LPCWSTR dll_path)
{
	/* Get Dll Image */
	PVOID dll_image = get_dll_by_file(dll_path);
	if (!dll_image)
	{
		printf(xor_a("[-] Invalid DLL\n"));
		return;
	}


	/* Parse NT Headers */
	PIMAGE_NT_HEADERS dll_nt_head = RtlImageNtHeader(dll_image);
	if (!dll_nt_head)
	{
		printf(xor_a("[-] Invalid PE Header.\n"));
		VirtualFree(dll_image, 0, MEM_RELEASE);
		return;
	}
	if (dll_nt_head->OptionalHeader.SizeOfImage == 0)
	{
		printf(xor_a("[-] Invalid image size.\n"));
		VirtualFree(dll_image, 0, MEM_RELEASE);
		return;
	}

	/* useless informations lol */
	DWORD thread_id = 0;
	DWORD process_id = get_process_id_and_thread_id_by_window_class(window_class_name, &thread_id);

	cout << xor_a("[+] Process ID: 0x") << hex << process_id << endl;
	cout << xor_a("[+] Thread  ID: 0x") << hex << thread_id << endl;

	if (process_id != 0 && thread_id != 0)
	{
		// attach target process
		drv::attach(process_id);

		PVOID allocate_base = drv::alloc(dll_nt_head->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
		cout << xor_a("[+] Allocated Base: 0x") << hex << allocate_base << endl;
		if (!allocate_base)
		{
			printf(xor_a("[-] Driver allocation failed.\n"));
			VirtualFree(dll_image, 0, MEM_RELEASE);
			return;
		}

		// fix reloc
		if (!relocate_image(allocate_base, dll_image, dll_nt_head))
		{
			drv::free_mem(allocate_base);
			printf(xor_a("[-] Relocation failed.\n"));
			VirtualFree(dll_image, 0, MEM_RELEASE);
			return;
		}

		printf(xor_a("[+] Successfully relocated image.\n"));

		// fix iat
		if (!resolve_import(thread_id, dll_image, dll_nt_head))
		{
			drv::free_mem(allocate_base);
			printf(xor_a("[-] Imports failed.\n"));
			VirtualFree(dll_image, 0, MEM_RELEASE);
			return;
		}

		printf(xor_a("[+] Successfully resolved imports.\n"));

		// write dll section's
		if (!write_sections(allocate_base, dll_image, dll_nt_head))
		{
			drv::free_mem(allocate_base);
			printf(xor_a("[-] Section write failed.\n"));
			VirtualFree(dll_image, 0, MEM_RELEASE);
			return;
		}

		printf(xor_a("[+] Successfully wrote sections\n"));

		// call dll main
		if (!call_dll_main(thread_id, allocate_base, dll_nt_head, false))
		{
			drv::free_mem(allocate_base);
			printf(xor_a("[-] DllMain call failed.\n"));
			VirtualFree(dll_image, 0, MEM_RELEASE);
			return;
		}

		printf(xor_a("[+] Called dllmain.\n"));

		// cleanup
		if (!erase_discardable_sect(allocate_base, dll_nt_head))
			printf(xor_a("[!] Some discardable sections could not be erased.\n"));
		VirtualFree(dll_image, 0, MEM_RELEASE);

		printf(xor_a("[+] Injected.\n"));
		cout << endl;
	}
	else
	{
		printf(xor_a("[-] Process not found.\n"));
	}
}
