<div align="center">
<h1>winarm64-svc</h1>
<h4>author: freefly</h4>

[English](README.md) | [简体中文](README_CN.md)

[![Language](https://img.shields.io/badge/Language-C++17-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B17)
[![Platform](https://img.shields.io/badge/Platform-Windows_on_ARM-lightgrey.svg)](https://en.wikipedia.org/wiki/Windows_on_ARM)
[![Build](https://img.shields.io/badge/Build-CMake-orange.svg)](https://en.wikipedia.org/wiki/CMake)

**A lightweight C++ PoC for indirect native calls on Windows on ARM64**

</div>

---

**winarm64-svc** is a Windows on ARM64 (WoA) research project for resolving native routines and calling `ntdll.dll` Native API stubs through a custom ARM64 assembly caller.

## Features

* Manually reads **TEB / PEB** to dynamically retrieve module base addresses.
* Manually parses PE export tables to resolve function addresses.
* Locates the real `SVC` instruction address from ARM64 `ntdll.dll` stubs.
* Calls ARM64 function addresses with a custom assembly caller.

## Further Reading

If you are interested in this project or want to learn more about the implementation details, 
please refer to the design documents: [doc/README.md](doc/README.md)
