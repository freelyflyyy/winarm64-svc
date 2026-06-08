#include "winarm64-svc.h"
#include "nt-structs.h"
#include <cstdio>

using namespace Nt;

DWORD64 GetTeb64() {
	return (DWORD64)__getReg(18);
}

DWORD64 GetPeb64() {
	// The PEB can be accessed via the TEB at offset 0x60
	DWORD64 teb = GetTeb64();
	return *(DWORD64*)(teb + 0x60);
}

DWORD64 GetNtdll64() {
	return GetModuleBase64(L"ntdll.dll");
}

DWORD64 GetKernel64()
{
	return GetModuleBase64(L"kernel32.dll");
}

DWORD64 GetModuleLdrEntry64(PCWSTR ModuleName) {
	auto* peb = (PEB64*)GetPeb64();
	auto* ldr = (PEB_LDR_DATA64*)peb->Ldr;
	DWORD64 head = peb->Ldr + FIELD_OFFSET(PEB_LDR_DATA64, InLoadOrderModuleList);
	DWORD64 current = ldr->InLoadOrderModuleList.Flink;
	while (current != head && current != 0) {
		auto* entry = (LDR_DATA_TABLE_ENTRY64*)current;
		if (entry->BaseDllName.Buffer != 0 && entry->BaseDllName.Length > 0) {
			if (_wcsnicmp((WCHAR*)entry->BaseDllName.Buffer, ModuleName, entry->BaseDllName.MaximumLength / sizeof(WCHAR)) == 0){
				return current;
			}
		}
		current = entry->InLoadOrderLinks.Flink;
	}
	return -1;
}

DWORD64 GetModuleBase64(PCWSTR ModuleName) {
	auto ldr = (LDR_DATA_TABLE_ENTRY64*) GetModuleLdrEntry64(ModuleName);
	return (DWORD64)ldr != -1 ? ldr->DllBase : -1;
}

DWORD64 GetProcAddress64(DWORD64 ModuleBase, PCSTR ProcName) {
	if (!ModuleBase || ModuleBase == -1 || !ProcName) {
		return -1;
	}
	auto* dosHeader = (IMAGE_DOS_HEADER*)ModuleBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { // 'MZ'
		return -1;
	}
	auto* ntHeaders = (IMAGE_NT_HEADERS64*)(ModuleBase + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) { // 'PE\0\0'
		return -1;
	}
	const auto& exportDirInfo = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!exportDirInfo.VirtualAddress || !exportDirInfo.Size) {
		return -1;
	}

	auto* exportDir = (IMAGE_EXPORT_DIRECTORY*)(ModuleBase + exportDirInfo.VirtualAddress);
	auto* nameRVAs = (DWORD*)(ModuleBase + exportDir->AddressOfNames);
	auto* funcRVAs = (DWORD*)(ModuleBase + exportDir->AddressOfFunctions);
	auto* ordinals = (WORD*)(ModuleBase + exportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
		const char* name = (const char*)(ModuleBase + nameRVAs[i]);
		if (strcmp(name, ProcName) == 0) {
			WORD funcIndex = ordinals[i];
			DWORD funcRVA = funcRVAs[funcIndex];
			if (funcRVA >= exportDirInfo.VirtualAddress && 
				funcRVA < exportDirInfo.VirtualAddress + exportDirInfo.Size){
				return -1; // Forwarded export
			}
			return ModuleBase + funcRVA;
		}
	}
	return -1;
}

DWORD64 GetServiceNumber64(DWORD64 ModuleBase, PCSTR ProcName) {
	if (!ModuleBase || !ProcName) {
		return -1;
	}
	auto funcAddr = GetProcAddress64(ModuleBase, ProcName);
	if (!funcAddr) {
		return -1;
	}

	/*
	* In my development environment, ARM64 ntdll syscall stubs
	* usually follow this pattern:
	*
	*     SVC     #imm
	*     RET
	*/

	auto getSvcAddress = [](auto&& self, DWORD64 funcAddr, WORD depth = 0) -> DWORD64 {
		if (depth >= 20) {
			return -1;
		}
		DWORD* instr = (DWORD*)funcAddr;
		//RET
		if (*instr == 0xD65F03C0) return -1;
		// find SVC
		if ((*instr & 0xFFE0001F) == 0xD4000001) {
			return funcAddr;
		}
		return self(self, funcAddr + 4, depth + 1);
		};
	return getSvcAddress(getSvcAddress, funcAddr);
}


int main() {
	DWORD64 teb = GetTeb64();
	printf("TEB64: 0x%llx\n", teb);
	DWORD64 peb = GetPeb64();
	printf("PEB64: 0x%llx\n", peb);
	DWORD64 ntdll = GetNtdll64();
	printf("ntdll.dll base: 0x%llx\n", ntdll);
	DWORD64 kernel = GetKernel64();
	printf("kernel32.dll base: 0x%llx\n", kernel);
	DWORD64 proc = GetProcAddress64(ntdll, "NtReadVirtualMemory");
	printf("NtReadVirtualMemory address: 0x%llx\n", proc);
	DWORD64 value = 0x1122334455667788;
	DWORD64 output = 0;
	SIZE_T bytesRead = 0;

	DWORD64 result = A64Call(
		proc,
		(DWORD64)-1,
		(DWORD64)&value,
		(DWORD64)&output,
		(DWORD64)sizeof(value),
		(DWORD64)&bytesRead
	);
	printf("NtReadVirtualMemory result: 0x%llx, output: 0x%llx, bytesRead: %llu\n", result, output, bytesRead);
	return 0;
}

