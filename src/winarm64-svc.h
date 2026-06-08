#pragma once

#include "win-headers.h"

DWORD64 GetTeb64();
DWORD64 GetPeb64();
DWORD64 GetNtdll64();
DWORD64 GetKernel64();
DWORD64 GetModuleLdrEntry64(PCWSTR ModuleName);
DWORD64 GetModuleBase64(PCWSTR ModuleName);
DWORD64 GetProcAddress64(DWORD64 ModuleBase, PCSTR ProcName);
DWORD64 GetServiceNumber64(DWORD64 ModuleBase, PCSTR ProcName);

extern "C" DWORD64 A64CallImpl(DWORD64 funcAddr, DWORD64 argCount, const DWORD64* args);

template<typename... Args>
DWORD64 A64Call(DWORD64 funcAddr, Args... args) {
	constexpr size_t argCount = sizeof...(Args);
	static_assert(argCount <= 8, "A64Call supports up to 8 arguments.");

	DWORD64 packedArgs[argCount > 0 ? argCount : 1] = { static_cast<DWORD64>(args)... };
	return A64CallImpl(funcAddr, argCount, packedArgs);
}
