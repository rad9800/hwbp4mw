//////////////////////////////////////////////////////////////////////////////////////////
/*                                  Detour Original Thread                              */
//////////////////////////////////////////////////////////////////////////////////////////

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


//////////////////////////////////////////////////////////////////////////////////////////
/*                                  Hook Suspended Thread                               */
//////////////////////////////////////////////////////////////////////////////////////////

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





