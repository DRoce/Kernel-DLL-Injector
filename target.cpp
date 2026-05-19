#include "Target.h"

#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>

std::vector<TargetProcess> Target::potential_targets = {
	{ "Fortnite", "FortniteClient-Win64-Shipping.exe", "target.dll", X64, false },
	{ "Crab Champions", "CrabChampions-Win64-Shipping.exe", "target.dll", X64, true },
};

int Target::is_valid_target(std::string target_name) {
	Architecture_t architecture = (Architecture_t)(sizeof(void*) == 8);

	for (size_t i = 0; i < potential_targets.size(); i++) {
		TargetProcess& potential_target = potential_targets.at(i);
		if (potential_target.architecture == architecture && potential_target.process_name.compare(target_name) == 0) {
			return (int)i;
		}
	}

	return -1;
}

int Target::find_target(TargetProcess* target) {
	if (!target)
		return -1;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return -1;

	PROCESSENTRY32 entry = { NULL };
	entry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &entry)) {
		CloseHandle(hSnapshot);
		return -1;
	}

	do {
		int potential_target_id = is_valid_target(entry.szExeFile);
		if (potential_target_id != -1) {
			CloseHandle(hSnapshot);
			*target = potential_targets.at(potential_target_id);
			target->process_id = (int)entry.th32ProcessID;
			return entry.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &entry));

	CloseHandle(hSnapshot);
	return -1;
}

void Target::print_potential_targets() {
	std::cout << "[*] Potential Targets:\n";
	for (size_t i = 0; i < potential_targets.size(); i++) {
		const auto& t = potential_targets.at(i);
		std::cout << "    [" << i << "] Display: " << t.display_name 
		          << " | EXE: " << t.process_name 
		          << " | DLL: " << t.dll_name << "\n";
	}
	std::cout << "\n";
}
