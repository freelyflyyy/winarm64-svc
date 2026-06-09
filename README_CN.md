<div align="center">
<h1>winarm64-svc</h1>
<h4>author: freefly</h4>

[English](README.md) | [简体中文](README_CN.md)

[![Language](https://img.shields.io/badge/Language-C++17-blue.svg)](https://en.wikipedia.org/wiki/C++17)
[![Platform](https://img.shields.io/badge/Platform-Windows_on_ARM-lightgrey.svg)](https://en.wikipedia.org/wiki/Windows_on_ARM)
[![Build](https://img.shields.io/badge/Build-CMake-orange.svg)](https://en.wikipedia.org/wiki/CMake)

**基于 C++ 的 Windows on ARM64 间接系统调用轻量级 PoC**

</div>

---

**winarm64-svc** 实现了 Windows on ARM64 (WoA) 架构下的原生函数解析与间接系统调用实验。项目通过动态解析模块、手动解析导出表，并结合自定义 ARM64 汇编调用器来调用 `ntdll.dll` 中的 Native API stub。

## 核心特性

* 手动读取 **TEB / PEB**，动态获取模块基址。
* 手动解析模块导出表以获取函数地址。
* 根据函数地址定位真实的 `SVC` 指令地址。
* 使用手写 ARM64 汇编调用器触发间接调用。

## 深入阅读

如果你对本项目感兴趣，或者想了解更多实现细节，
请阅读设计文档：[doc/README_CN.md](doc/README_CN.md)
