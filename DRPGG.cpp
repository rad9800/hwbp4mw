//////////////////////////////////////////////////////////////////////////////////////////
/*                                      DRPGG.cpp - @rad9800                            */
/*                           C++ PAGE_GUARD/HWBP Breakpoint Library   c++20             */
//////////////////////////////////////////////////////////////////////////////////////////
#include <windows.h>

#include <tlhelp32.h>
#include <functional>	// std::function 


using EXCEPTION_FUNC = std::function <void(PEXCEPTION_POINTERS)>;

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Structs                                     */
//////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
	UINT										pos;
	EXCEPTION_FUNC								func;
} HWBP_CALLBACK;

typedef struct {
	EXCEPTION_FUNC								func;
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
/*                                          Globals                                     */
//////////////////////////////////////////////////////////////////////////////////////////

// maintain our address -> lambda function mapping 
std::unordered_map<uintptr_t, HWBP_CALLBACK> HWBP_ADDRESS_MAP{ 0 };
std::unordered_map<uintptr_t, PG_CALLBACK>	PG_ADDRESS_MAP{ 0 };

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Funcs                                       */
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
/*                                      Exception Handler                               */
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
/*                                        Classes                                       */
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
	UINT			pos;
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
/*                                          Entry                                       */
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
			ExceptionInfo->ContextRecord->EFlags |= (1 << 16);	// continue execution
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
/*                                         EOF                                          */
//////////////////////////////////////////////////////////////////////////////////////////
