<div align="center">
<h1>winarm64-svc</h1>
<h5>author: freefly</h5>

[English](README.md) | [简体中文](README_CN.md)

</div>

---

## 前言

本项目主要用于 Windows on ARM64 学习、实验和逆向分析。Windows 内部结构与
`ntdll.dll` stub 属于实现细节，不保证在不同 Windows 版本之间保持稳定。

---

## 函数

### `DWORD64 GetTeb64();`

返回当前线程的 TEB 地址。

在 Windows ARM64 中，`x18` 寄存器通常指向当前线程的 TEB。汇编实现
直接返回 `x18`：

```asm
mov x0, x18
ret
```

返回值：

- 当前线程 TEB 地址。


### `DWORD64 GetPeb64();`

返回当前进程的 PEB 地址。

PEB 指针从当前 TEB 的 `0x60` 偏移处读取：

```asm
ldr x0, [x18, #0x60]
ret
```

返回值：

- 当前进程 PEB 地址。


### `DWORD64 GetNtdll64();`

返回 `ntdll.dll` 的模块基址。

内部调用：

```cpp
GetModuleBase64(L"ntdll.dll")
```

返回值：

- `ntdll.dll` 基址；
- 失败返回 `(DWORD64)-1`。

### `DWORD64 GetKernel64();`

返回 `kernel32.dll` 的模块基址。

内部调用：

```cpp
GetModuleBase64(L"kernel32.dll")
```

返回值：

- `kernel32.dll` 基址；
- 失败返回 `(DWORD64)-1`。


### `DWORD64 GetModuleLdrEntry64(PCWSTR ModuleName);`

在当前进程的 Loader 链表中查找模块条目。

该函数从当前 PEB 开始，读取 `PEB->Ldr`，然后遍历
`InLoadOrderModuleList`。每个链表项按 `LDR_DATA_TABLE_ENTRY64` 解释，并使用
`BaseDllName` 与 `ModuleName` 进行比较。

查找路径：

```text
TEB
  -> PEB
  -> PEB_LDR_DATA
  -> InLoadOrderModuleList
  -> LDR_DATA_TABLE_ENTRY64
```

参数：

- `ModuleName` - Unicode 模块名，例如 `L"ntdll.dll"`。

返回值：

- 匹配模块的 Loader 条目地址；
- 失败返回 `(DWORD64)-1`。

### `DWORD64 GetModuleBase64(PCWSTR ModuleName);`

查找已加载模块的基址。

内部调用 `GetModuleLdrEntry64()`，并返回匹配
`LDR_DATA_TABLE_ENTRY64` 中的 `DllBase` 字段。

参数：

- `ModuleName` - Unicode 模块名，例如 `L"kernel32.dll"`。

返回值：

- 模块基址；
- 失败返回 `(DWORD64)-1`。

### `DWORD64 GetProcAddress64(DWORD64 ModuleBase, PCSTR ProcName);`

从已加载模块中解析导出函数地址。

该函数手动解析 PE 导出目录：

```text
ModuleBase
  -> IMAGE_DOS_HEADER
  -> IMAGE_NT_HEADERS64
  -> IMAGE_EXPORT_DIRECTORY
  -> AddressOfNames
  -> AddressOfNameOrdinals
  -> AddressOfFunctions
```

找到目标函数名后，将导出 RVA 转换为虚拟地址：

```cpp
functionAddress = ModuleBase + functionRva;
```

参数：

- `ModuleBase` - 目标模块基址。
- `ProcName` - ANSI 导出函数名。

返回值：

- 函数地址；
- 失败返回 `(DWORD64)-1`。

说明：

- 当前会拒绝 forwarded export，并返回 `(DWORD64)-1`；
- 当前只支持按名称解析。

### `DWORD64 GetServiceAddress64(DWORD64 ModuleBase, PCSTR ProcName);`

定位导出 Native API stub 中使用的 `SVC` 指令。

该函数首先通过 `GetProcAddress64()` 解析 `ProcName`，然后从函数入口开始按
4 字节步进向后扫描，因为 AArch64 指令固定为 4 字节宽度。

扫描遇到以下情况之一会停止：

- ARM64 `SVC #imm` 指令；
- ARM64 `RET` 指令；
- 达到扫描深度限制。

`SVC` 指令匹配方式：

```cpp
(instruction & 0xFFE0001F) == 0xD4000001
```

参数：

- `ModuleBase` - 模块基址，通常是 `ntdll.dll`。
- `ProcName` - ANSI Native API 名，例如 `"NtReadVirtualMemory"`。

返回值：

- 定位到的 `SVC` 指令地址；
- 失败返回 `(DWORD64)-1`。

说明：

- 返回的是 trap 指令地址，不是原始函数入口；
- ARM64 `svc #imm` 的立即数编码在指令中，不能通过普通通用寄存器在运行时传入。


### `DWORD64 A64CallImpl(DWORD64 funcAddr, DWORD64 argCount, const DWORD64* args);`

底层 ARM64 汇编调用器，用于调用一个地址，并最多传递 8 个整数或指针参数。

参数：

- `funcAddr` - 要调用的地址。
- `argCount` - `args` 中的参数数量，范围必须为 0 到 8。
- `args` - 指向 64 位参数数组的指针。

调用约定：

```text
x0-x7  前 8 个整数或指针参数
x0     返回值
blr    调用寄存器中的地址
```

汇编实现会将 `args[0]` 到 `args[7]` 分别加载到 `x0` 到 `x7`，然后使用
`blr` 调用 `funcAddr`。

返回值：

- 被调用函数返回的原始 64 位返回值。

限制：

- 最多支持 8 个参数；
- 仅支持整数和指针类参数；
- 不支持浮点参数；
- 不支持结构体返回约定；
- 不处理栈上传参。

### `template<typename... Args> DWORD64 A64Call(DWORD64 funcAddr, Args... args);`

`A64CallImpl()` 的 C++ 模板封装。

该封装会把所有参数打包到临时 `DWORD64` 数组中，然后将参数数量和数组指针
传给 `A64CallImpl()`。

示例：

```cpp
DWORD64 result = A64Call(
    functionAddress,
    (DWORD64)arg0,
    (DWORD64)arg1,
    (DWORD64)arg2
);
```

参数：

- `funcAddr` - 要调用的地址。
- `args` - 最多 8 个可转换为 `DWORD64` 的值。

返回值：

- 被调用函数返回的原始 64 位返回值。

说明：

- 模板中包含最多 8 参数的编译期检查；
- 指针参数建议根据需要显式转换为 `DWORD64`。


### `A64Syscall(funcAddr, ...)`

通过 `A64Call()` 调用地址的便捷宏。

当前定义：

```cpp
#define A64Syscall(funcAddr, ...) A64Call(funcAddr, __VA_ARGS__)
```

示例：

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

说明：

- 该宏不会动态编码 `SVC #imm` 指令；
- 它只会调用调用者传入的地址；
- 当前项目中，`GetServiceAddress64()` 用于定位 `ntdll.dll` Native API stub 中的
  `SVC` 指令地址。

---
## 示例

当前示例会解析 `NtReadVirtualMemory`，定位其 `SVC` 指令，并用一个本地读取
测试调用它：

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

预期成功结果：

```text
NtReadVirtualMemory result: 0x0
output: 0x1122334455667788
bytesRead: 8
```

`0x0` 表示 `STATUS_SUCCESS`。

--------------------------------------------------------------------------------

## IDA 辅助脚本

仓库中还包含一个 IDA Python 辅助脚本：

```text
ida-utils/scan_arm64_syscall.py
```

它会扫描 ARM64 `ntdll.dll` 中导出的 `Nt*` 和 `Zw*` 函数，并分类 syscall
stub 模式：

- 直接 `SVC #imm`；
- `SVC` 前存在 `MOV W8/X8, #imm`；
- 扫描窗口内未找到 `SVC`。

该脚本适合用于比较不同 Windows ARM64 版本中的 syscall stub 布局。

--------------------------------------------------------------------------------

## 构建说明

项目使用 CMake 和 Microsoft ARM64 工具链。

需要的工具：

- 带 MSVC ARM64 build tools 的 Visual Studio；
- CMake；
- Ninja；
- `armasm64`。

汇编文件必须使用 ARM64 汇编器编译，而不是 x86 MASM。

---
## 注意事项

- 本项目依赖 Windows 内部结构。
- TEB 中 PEB 指针等偏移可能在未来版本中变化。
- `ntdll.dll` syscall stub 属于实现细节，不同 Windows 版本可能不同。
- AArch64 指令固定为 4 字节，因此扫描 stub 时应该按 4 字节步进，而不是按
  1 字节步进。
- `SVC #imm` 的立即数编码在指令中。单个通用汇编函数无法直接执行一个运行时
  动态选择的立即数，除非生成或选择包含该立即数的代码。

---