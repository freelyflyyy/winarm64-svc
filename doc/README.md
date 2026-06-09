<div align="center">
<h1>winarm64-svc</h1>
<h4>author: freefly</h4>

[English](README.md) | [Simplified Chinese](README_CN.md)

</div>

---

## Preface

This project is mainly intended for learning, experimentation, and reverse
engineering on Windows on ARM64. Windows internal structures and `ntdll.dll`
stubs are implementation details and are not guaranteed to remain stable across
different Windows versions.

---

## Functions

### `DWORD64 GetTeb64();`

Returns the address of the current thread's TEB.

On Windows ARM64, register `x18` usually points to the current thread's TEB. The
assembly implementation returns `x18` directly:

```asm
mov x0, x18
ret
```

Return value:

- current thread TEB address.


### `DWORD64 GetPeb64();`

Returns the address of the current process PEB.

The PEB pointer is read from offset `0x60` of the current TEB:

```asm
ldr x0, [x18, #0x60]
ret
```

Return value:

- current process PEB address.


### `DWORD64 GetNtdll64();`

Returns the module base address of `ntdll.dll`.

Internally calls:

```cpp
GetModuleBase64(L"ntdll.dll")
```

Return value:

- base address of `ntdll.dll`;
- `(DWORD64)-1` on failure.

### `DWORD64 GetKernel64();`

Returns the module base address of `kernel32.dll`.

Internally calls:

```cpp
GetModuleBase64(L"kernel32.dll")
```

Return value:

- base address of `kernel32.dll`;
- `(DWORD64)-1` on failure.


### `DWORD64 GetModuleLdrEntry64(PCWSTR ModuleName);`

Finds a module entry in the current process loader list.

This function starts from the current PEB, reads `PEB->Ldr`, and then walks
`InLoadOrderModuleList`. Each list item is interpreted as a
`LDR_DATA_TABLE_ENTRY64`, and `BaseDllName` is compared with `ModuleName`.

Lookup path:

```text
TEB
  -> PEB
  -> PEB_LDR_DATA
  -> InLoadOrderModuleList
  -> LDR_DATA_TABLE_ENTRY64
```

Parameters:

- `ModuleName` - Unicode module name, for example `L"ntdll.dll"`.

Return value:

- address of the matched loader entry;
- `(DWORD64)-1` on failure.

### `DWORD64 GetModuleBase64(PCWSTR ModuleName);`

Finds the base address of a loaded module.

Internally calls `GetModuleLdrEntry64()` and returns the `DllBase` field from the
matched `LDR_DATA_TABLE_ENTRY64`.

Parameters:

- `ModuleName` - Unicode module name, for example `L"kernel32.dll"`.

Return value:

- module base address;
- `(DWORD64)-1` on failure.

### `DWORD64 GetProcAddress64(DWORD64 ModuleBase, PCSTR ProcName);`

Resolves an exported function address from a loaded module.

This function manually parses the PE export directory:

```text
ModuleBase
  -> IMAGE_DOS_HEADER
  -> IMAGE_NT_HEADERS64
  -> IMAGE_EXPORT_DIRECTORY
  -> AddressOfNames
  -> AddressOfNameOrdinals
  -> AddressOfFunctions
```

After the target function name is found, the export RVA is converted to a
virtual address:

```cpp
functionAddress = ModuleBase + functionRva;
```

Parameters:

- `ModuleBase` - target module base address.
- `ProcName` - ANSI exported function name.

Return value:

- function address;
- `(DWORD64)-1` on failure.

Notes:

- forwarded exports are currently rejected and return `(DWORD64)-1`;
- only name-based resolution is currently supported.

### `DWORD64 GetServiceAddress64(DWORD64 ModuleBase, PCSTR ProcName);`

Locates the `SVC` instruction used by an exported Native API stub.

This function first resolves `ProcName` through `GetProcAddress64()`, then scans
forward from the function entry in 4-byte steps because AArch64 instructions are
fixed-width 4-byte instructions.

The scan stops when one of the following is encountered:

- an ARM64 `SVC #imm` instruction;
- an ARM64 `RET` instruction;
- the scan depth limit.

The `SVC` instruction is matched with:

```cpp
(instruction & 0xFFE0001F) == 0xD4000001
```

Parameters:

- `ModuleBase` - module base address, normally `ntdll.dll`.
- `ProcName` - ANSI Native API name, for example `"NtReadVirtualMemory"`.

Return value:

- address of the located `SVC` instruction;
- `(DWORD64)-1` on failure.

Notes:

- the returned address is the trap instruction address, not the original
  function entry;
- the immediate value of ARM64 `svc #imm` is encoded in the instruction and
  cannot be supplied through a normal general-purpose register at runtime.


### `DWORD64 A64CallImpl(DWORD64 funcAddr, DWORD64 argCount, const DWORD64* args);`

Low-level ARM64 assembly caller used to call an address with up to 8 integer or
pointer arguments.

Parameters:

- `funcAddr` - address to call.
- `argCount` - number of values in `args`; must be in the range 0 to 8.
- `args` - pointer to an array of 64-bit argument values.

Calling convention:

```text
x0-x7  first 8 integer or pointer arguments
x0     return value
blr    call an address stored in a register
```

The assembly implementation loads `args[0]` through `args[7]` into `x0` through
`x7`, then calls `funcAddr` with `blr`.

Return value:

- raw 64-bit return value from the called routine.

Limitations:

- supports at most 8 arguments;
- supports only integer and pointer-like arguments;
- does not support floating-point arguments;
- does not support structure return conventions;
- does not handle stack arguments.

### `template<typename... Args> DWORD64 A64Call(DWORD64 funcAddr, Args... args);`

C++ template wrapper for `A64CallImpl()`.

The wrapper packs all parameters into a temporary `DWORD64` array, then passes
the argument count and array pointer to `A64CallImpl()`.

Example:

```cpp
DWORD64 result = A64Call(
    functionAddress,
    (DWORD64)arg0,
    (DWORD64)arg1,
    (DWORD64)arg2
);
```

Parameters:

- `funcAddr` - address to call.
- `args` - up to 8 values convertible to `DWORD64`.

Return value:

- raw 64-bit return value from the called routine.

Notes:

- the template includes a compile-time check for the 8-argument limit;
- pointer arguments should be explicitly cast to `DWORD64` when needed.


### `A64Syscall(funcAddr, ...)`

Convenience macro for calling an address through `A64Call()`.

Current definition:

```cpp
#define A64Syscall(funcAddr, ...) A64Call(funcAddr, __VA_ARGS__)
```

Example:

```cpp
DWORD64 result = A64Syscall(
    svcAddress,
    (DWORD64)-1,
    (DWORD64)&value,
    (DWORD64)&output,
    (DWORD64)sizeof(value),
    (DWORD64)&bytesRead
);
```

Notes:

- this macro does not dynamically encode an `SVC #imm` instruction;
- it only calls the address supplied by the caller;
- in the current project, `GetServiceAddress64()` is used to locate the `SVC`
  instruction address in an `ntdll.dll` Native API stub.

---
## Example

The current sample resolves `NtReadVirtualMemory`, locates its `SVC`
instruction, and calls it with a small local read test:

```cpp
DWORD64 ntdll = GetNtdll64();
DWORD64 svcAddress = GetServiceAddress64(ntdll, "NtReadVirtualMemory");

DWORD64 value = 0x1122334455667788;
DWORD64 output = 0;
SIZE_T bytesRead = 0;

DWORD64 result = A64Syscall(
    svcAddress,
    (DWORD64)-1,
    (DWORD64)&value,
    (DWORD64)&output,
    (DWORD64)sizeof(value),
    (DWORD64)&bytesRead
);
```

Expected successful result:

```text
NtReadVirtualMemory result: 0x0
output: 0x1122334455667788
bytesRead: 8
```

`0x0` means `STATUS_SUCCESS`.

--------------------------------------------------------------------------------

## IDA helper script

The repository also contains an IDA Python helper script:

```text
ida-utils/scan_arm64_syscall.py
```

It scans exported `Nt*` and `Zw*` functions in ARM64 `ntdll.dll` and classifies
syscall stub patterns:

- direct `SVC #imm`;
- `MOV W8/X8, #imm` before `SVC`;
- no `SVC` found in the scan window.

This script is useful for comparing syscall stub layouts across different
Windows ARM64 versions.

--------------------------------------------------------------------------------

## Build notes

The project uses CMake and the Microsoft ARM64 toolchain.

Required tools:

- Visual Studio with MSVC ARM64 build tools;
- CMake;
- Ninja;
- `armasm64`.

The assembly file must be built with the ARM64 assembler, not x86 MASM.

---
## Notes

- This project depends on Windows internal structures.
- Offsets such as the PEB pointer inside the TEB may change in future versions.
- `ntdll.dll` syscall stubs are implementation details and may differ between
  Windows versions.
- AArch64 instructions are fixed 4-byte instructions, so stub scanning should
  advance by 4 bytes instead of 1 byte.
- The immediate value of `SVC #imm` is encoded in the instruction. A single
  generic assembly function cannot directly execute a runtime-selected
  immediate value unless it generates or selects code containing that immediate.

---
