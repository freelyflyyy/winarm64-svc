#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
