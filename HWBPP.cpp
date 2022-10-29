//////////////////////////////////////////////////////////////////////////////////////////
/*                                      HWBPP.cpp - @rad9800                            */
/*                         C++ Hardware Breakpoint Library (DLL example)                */
//////////////////////////////////////////////////////////////////////////////////////////
// dllmain.cpp : Defines the entry point for the DLL application.
// /std:c++20
#include "pch.h"
#include <windows.h>

#include <tlhelp32.h>
#include <functional>

using EXCEPTION_FUNC = std::function <void(PEXCEPTION_POINTERS)>;

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Structs                                     */
//////////////////////////////////////////////////////////////////////////////////////////
typedef struct {
	UINT										pos;
	EXCEPTION_FUNC								func;
} HWBP_CALLBACK;

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Globals                                     */
//////////////////////////////////////////////////////////////////////////////////////////
// maintain our address -> lambda function mapping 
std::unordered_map<uintptr_t, HWBP_CALLBACK> HWBP_ADDRESS_MAP{ 0 };

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Funcs                                       */
//////////////////////////////////////////////////////////////////////////////////////////
VOID SetHWBP(const HANDLE thd, const uintptr_t address, const UINT pos, const bool init)
{
	CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thd, &context);

	if (init) {
		(&context.Dr0)[pos] = address;

		context.Dr7 &= ~(3ull << (16 + 4 * pos));
		context.Dr7 &= ~(3ull << (18 + 4 * pos));
		context.Dr7 |= 1ull << (2 * pos);
	}
	else {
		if ((&context.Dr0)[pos] == address) {
			context.Dr7 &= ~(1ull << (2 * pos));
			(&context.Dr0)[pos] = NULL;
		}
	}

	SetThreadContext(thd, &context);
}

VOID SetHWBPS(const uintptr_t address, const UINT pos, const bool init = true)
{
	const DWORD pid{ GetCurrentProcessId() };
	const HANDLE h{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te{ .dwSize = sizeof(THREADENTRY32) };
		if (Thread32First(h, &te)) {
			do {
				if ((te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)) && te.th32OwnerProcessID == pid) {

					const HANDLE thd = 
									OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
					if (thd != INVALID_HANDLE_VALUE) {
						SetHWBP(thd, address, pos, init);
						CloseHandle(thd);
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                      Exception Handler                               */
//////////////////////////////////////////////////////////////////////////////////////////
LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		if (HWBP_ADDRESS_MAP.contains(ExceptionInfo->ContextRecord->Rip)) {
			HWBP_ADDRESS_MAP.at(ExceptionInfo->ContextRecord->Rip).func(ExceptionInfo);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                        Classes                                       */
//////////////////////////////////////////////////////////////////////////////////////////
template<typename HANDLER>
struct HWBP {
public:
	HWBP(const uintptr_t address, const UINT idx,
		const HANDLER function) : address{ address } , pos{idx % 4}
	{
		SetHWBPS(address, pos);

		HWBP_ADDRESS_MAP[address].func = function;
		HWBP_ADDRESS_MAP[address].pos = pos;
	};

	VOID RemoveHWBPS()
	{
		SetHWBPS(address, pos, false);
		HWBP_ADDRESS_MAP.erase(address);
	}

	~HWBP()
	{
		RemoveHWBPS();
	}

private:
	const uintptr_t address;
	UINT			pos;
};


// Global Scope 
HWBP HWBPSleep{ (uintptr_t)&Sleep, 0,
	([&](PEXCEPTION_POINTERS ExceptionInfo) { 
		ExceptionInfo->ContextRecord->Rcx = 0;
		ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
}) };
//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Entry                                       */
//////////////////////////////////////////////////////////////////////////////////////////
extern "C" 
BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) 
{
	HANDLE handler = NULL;
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH: {
		handler = AddVectoredExceptionHandler(1, ExceptionHandler);
	}; break;
	case DLL_THREAD_ATTACH: {
	} break;
	case DLL_THREAD_DETACH: {

	}; break;
	case DLL_PROCESS_DETACH: {
		if (handler != nullptr) RemoveVectoredExceptionHandler(handler);
	}; break;
    }
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                         EOF                                          */
//////////////////////////////////////////////////////////////////////////////////////////
