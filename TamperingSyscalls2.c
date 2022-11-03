//////////////////////////////////////////////////////////////////////////////////////////
/*                           TamperingSyscalls2.c - @rad9800                            */
/*             C Generic x64 user-land evasion technique utilizing debug registers      */
/*                   Hides up to 12 args of up to 4 NT calls per thread                 */
//////////////////////////////////////////////////////////////////////////////////////////
#include <Windows.h>
#include <stdio.h>

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Macros                                      */
////////////////////////////////////////////////////////////////////////////////////////// 
#define STK_ARGS 8 // 8 (stack args) + 4 (fast-four)             
// Can be increased if needed (though you've got a problem if you need more threads)
#define MAX_THREAD_COUNT 64    
#define MAX_DEBUG_REGISTERS (MAX_THREAD_COUNT * 4)

#define _DEBUG 1 // 0 (disabled) / 1 (enabled) 

#if _DEBUG == 0
#define PRINT( ... )
#else
#define PRINT printf
#endif

#define PRINT_ARGS( State, ExceptionInfo, address )                     \
PRINT("%s %d arguments and stack for 0x%p || TID : 0x%x\n",             \
    State, (STK_ARGS + 4), (PVOID)address, GetCurrentThreadId());       \
PRINT("1:\t0x%p\n", (PVOID)(ExceptionInfo)->ContextRecord->Rcx);        \
PRINT("2:\t0x%p\n", (PVOID)(ExceptionInfo)->ContextRecord->Rdx);        \
PRINT("3:\t0x%p\n", (PVOID)(ExceptionInfo)->ContextRecord->R8);         \
PRINT("4:\t0x%p\n", (PVOID)(ExceptionInfo)->ContextRecord->R9);         \
for (UINT idx = 0; idx < STK_ARGS; idx++){                              \
    const size_t offset = idx * 0x8 + 0x28;                             \
    PRINT("%d:\t0x%p\n", (idx + 5), (PVOID)*(PULONG64)                  \
        ((ExceptionInfo)->ContextRecord->Rsp + offset));                \
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Typedefs                                    */
//////////////////////////////////////////////////////////////////////////////////////////
typedef struct {
    uintptr_t            rcx;    // First
    uintptr_t            rdx;    // Second
    uintptr_t            r8;        // Third
    uintptr_t            r9;        // Fourth
    uintptr_t            rsp[STK_ARGS];    // Stack args
} function_args;

typedef struct {
    function_args function_args;
    uintptr_t  function_address;
    uintptr_t  sys_call_address;
    DWORD     key_thread_id_val;
    UINT     debug_register_pos;
} sys_call_descriptor;

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Globals                                     */
//////////////////////////////////////////////////////////////////////////////////////////
sys_call_descriptor sys_call_descriptors[MAX_DEBUG_REGISTERS];
CRITICAL_SECTION    g_critical_section;


//////////////////////////////////////////////////////////////////////////////////////////
/*                                      Exception Handler                               */
//////////////////////////////////////////////////////////////////////////////////////////
/*
 * Function: exception_handler
 * -----------------------------------------
 *  sys_call handler required to save and modify the arguments to syscall
 *  instructions
 *
 *    Registered by init_tampering_sys_call
 *
 */
LONG WINAPI exception_handler(const PEXCEPTION_POINTERS ExceptionInfo)
{
    const uintptr_t exception_address = ExceptionInfo->ContextRecord->Rip;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        BOOL resolved = FALSE;
        EnterCriticalSection(&g_critical_section);

        for (size_t i = 0; i < MAX_DEBUG_REGISTERS; i++)
        {
            if (exception_address == sys_call_descriptors[i].function_address)
            {
                (&ExceptionInfo->ContextRecord->Dr0)[sys_call_descriptors[i].\
                    debug_register_pos] =
                    sys_call_descriptors[i].sys_call_address;

                sys_call_descriptors[i].function_args.rcx =
                    ExceptionInfo->ContextRecord->Rcx;
                sys_call_descriptors[i].function_args.rdx =
                    ExceptionInfo->ContextRecord->Rdx;
                sys_call_descriptors[i].function_args.r8 =
                    ExceptionInfo->ContextRecord->R8;
                sys_call_descriptors[i].function_args.r9 =
                    ExceptionInfo->ContextRecord->R9;

                for (unsigned j = 0; j < STK_ARGS; j++) {
                    const size_t offset = j * 0x8 + 0x28;
                    sys_call_descriptors[i].function_args.rsp[j] =
                        *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset);
                }

                PRINT_ARGS("HIDING", ExceptionInfo, exception_address);

                ExceptionInfo->ContextRecord->Rcx = 0ull;
                ExceptionInfo->ContextRecord->Rdx = 0ull;
                ExceptionInfo->ContextRecord->R8 = 0ull;
                ExceptionInfo->ContextRecord->R9 = 0ull;

                memset(
                    (PVOID)(ExceptionInfo->ContextRecord->Rsp + 0x28), 
                    0, 
                    STK_ARGS * sizeof(uintptr_t)
                );

                PRINT_ARGS("HIDDEN", ExceptionInfo, exception_address);

                resolved = TRUE;
            }
            else if (exception_address == sys_call_descriptors[i].sys_call_address)
            {
                (&ExceptionInfo->ContextRecord->Dr0)[sys_call_descriptors[i].\
                    debug_register_pos] =
                    sys_call_descriptors[i].function_address;

                ExceptionInfo->ContextRecord->R10 =
                    sys_call_descriptors[i].function_args.rcx;
                ExceptionInfo->ContextRecord->Rdx =
                    sys_call_descriptors[i].function_args.rdx;
                ExceptionInfo->ContextRecord->R8 =
                    sys_call_descriptors[i].function_args.r8;
                ExceptionInfo->ContextRecord->R9 =
                    sys_call_descriptors[i].function_args.r9;

                for (unsigned j = 0; j < STK_ARGS; j++) {
                    const size_t offset = j * 0x8 + 0x28;
                    *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) =
                        sys_call_descriptors[i].function_args.rsp[j];
                }

                PRINT_ARGS("RESTORED", ExceptionInfo, exception_address);

                resolved = TRUE;
            }
            if (resolved) break;
        }
        LeaveCriticalSection(&g_critical_section);

        if (resolved)
        {
            ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Resume Flag
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                      Functions                                       */
//////////////////////////////////////////////////////////////////////////////////////////

uintptr_t
find_gadget(
    const uintptr_t function,
    const BYTE* stub,
    const UINT size
)
{
    for (unsigned int i = 0; i < 25u; i++)
    {
        if (memcmp((LPVOID)(function + i), stub, size) == 0) {
            return (function + i);
        }
    }
    return 0ull;
}

/*
 * Function: set_hardware_breakpoint
 * ---------------------------------
 *  sets/removes a hardware breakpoint in the specified debug register for a specific
 *    function address
 *
 *    thd: A handle to the thread (GetCurrentThread)
 *    address: address of function to point a debug register towards
 *    pos: Dr[0-3]
 *    init: TRUE (Sets)/FALSE (Removes)
 *
 */
void
set_hardware_breakpoint(
    const HANDLE thd,
    const uintptr_t address,
    const UINT pos,
    const BOOL init
)
{
    BOOL modified = FALSE;
    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

    GetThreadContext(thd, &context);
    if (init) {
        (&context.Dr0)[pos] = address;
        context.Dr7 &= ~(3ull << (16 + 4 * pos));
        context.Dr7 &= ~(3ull << (18 + 4 * pos));
        context.Dr7 |= 1ull << (2 * pos);

        modified = TRUE;
    }
    else {
        if ((&context.Dr0)[pos] == address) {
            context.Dr7 &= ~(1ull << (2 * pos));
            (&context.Dr0)[pos] = 0ull;

            modified = TRUE;
        }
    }
    if (modified) {
        SetThreadContext(thd, &context);
    }
}

/*
 * Function: clear_sys_call_descriptor_entry
 * -----------------------------------------
 *  Zeroes out the parameters of a sys_call_descriptor
 *
 *    sys_call_descriptor: pointer to sys_call_descriptor
 *
 */
void
clear_sys_call_descriptor_entry(
    sys_call_descriptor* p_sys_call_descriptor
)
{
    memset(
        p_sys_call_descriptor, 
        0, 
        sizeof(sys_call_descriptor)
    );
}

/*
 * Function: init_tampering_sys_call
 * ---------------------------------
 *  initializes the structures and globals required
 *
 * returns: handler to the exception handler (can be removed with
 *          RemoveVectoredExceptionHandler.
 *
 */
PVOID
init_tampering_sys_call(
    void
)
{
    const PVOID handler = AddVectoredExceptionHandler(1, exception_handler);
    InitializeCriticalSection(&g_critical_section);

    for (size_t i = 0; i < MAX_DEBUG_REGISTERS; i++)
    {
        clear_sys_call_descriptor_entry(&sys_call_descriptors[i]);
    }

    return handler;
}


/*
 * Function: un_init_tampering_sys_call
 * ---------------------------------
 *  Un-initializes the structures and globals required and disables
 *  all currently enabled hardware breakpoints pertaining to tampering
 *  sys_calls.
 *
 */
void
un_init_tampering_sys_call(
    const PVOID handler
)
{
    EnterCriticalSection(&g_critical_section);

    for (unsigned int i = 0; i < MAX_DEBUG_REGISTERS; i++)
    {
        if (sys_call_descriptors[i].function_address != 0
            && sys_call_descriptors[i].key_thread_id_val != 0)
        {
            HANDLE thd = OpenThread(THREAD_ALL_ACCESS, FALSE,
                sys_call_descriptors[i].key_thread_id_val);

            set_hardware_breakpoint(
                thd,
                sys_call_descriptors[i].function_address,
                sys_call_descriptors[i].debug_register_pos,
                FALSE
            );

            if (thd != INVALID_HANDLE_VALUE) {
                CloseHandle(thd);
            }

            clear_sys_call_descriptor_entry(&sys_call_descriptors[i]);
            break;
        }
    }

    LeaveCriticalSection(&g_critical_section);

    RemoveVectoredExceptionHandler(handler);

    DeleteCriticalSection(&g_critical_section);
}

/*
 * Function: set_tampering_sys_call
 * --------------------------------
 *  sets the hardware breakpoint, and adds the required entries to global
 *  structures
 *
 * nt_function_address: & of NT function
 * pos: Debug register position (0-3)
 *
 */
void
set_tampering_sys_call(
    const uintptr_t nt_function_address,
    const UINT pos
)
{
    const UINT idx = pos % 4;
    const BYTE sys_call_op_code[] = { 0x0F, 0x05 };
    const uintptr_t nt_sys_call_address =
        find_gadget(nt_function_address, sys_call_op_code, 2);

    // Perform only required work when inside critical section.
    EnterCriticalSection(&g_critical_section);

    for (unsigned int i = 0; i < MAX_DEBUG_REGISTERS; i++)
    {
        if (sys_call_descriptors[i].function_address == 0)
        {
            sys_call_descriptors[i].function_address = nt_function_address;
            sys_call_descriptors[i].sys_call_address = nt_sys_call_address;

            sys_call_descriptors[i].debug_register_pos = idx;
            sys_call_descriptors[i].key_thread_id_val = GetCurrentThreadId();

            break;
        }
    }

    LeaveCriticalSection(&g_critical_section);

    set_hardware_breakpoint(
        GetCurrentThread(),
        nt_function_address,
        idx,
        TRUE
    );
}

/*
 * Function: remove_tampering_sys_call
 * -----------------------------------
 *  Destroys all objects and debug registers set during init or use.
 *
 * nt_function_address: & of NT function
 * pos: Debug register position (0-3)
 *
 */
void
remove_tampering_sys_call(
    const uintptr_t nt_function_address,
    const UINT pos
)
{
    EnterCriticalSection(&g_critical_section);

    for (unsigned int i = 0; i < MAX_DEBUG_REGISTERS; i++)
    {
        if (sys_call_descriptors[i].function_address == nt_function_address
            && sys_call_descriptors[i].key_thread_id_val == GetCurrentThreadId())
        {
            clear_sys_call_descriptor_entry(&sys_call_descriptors[i]);
            break;
        }
    }

    LeaveCriticalSection(&g_critical_section);

    set_hardware_breakpoint(
        GetCurrentThread(),
        nt_function_address,
        pos % 4,
        FALSE
    );
}


DWORD WINAPI
test_thread(
    LPVOID lp_parameter
)
{
    PRINT("---- New Thread ----\n");

    set_tampering_sys_call(
        (uintptr_t)GetProcAddress(GetModuleHandleW(L"NTDLL.dll"),
            "NtCreateMutant"),
        1
    );

    HANDLE m = CreateMutexA(NULL, TRUE, "rad98");
    if (m) CloseHandle(m);

    // Not really needed as thread returns, but it's good practice.
    remove_tampering_sys_call(
        (uintptr_t)GetProcAddress(GetModuleHandleW(L"NTDLL.dll"),
            "NtCreateMutant"),
        1
    );
    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Entry                                       */
//////////////////////////////////////////////////////////////////////////////////////////

int main()
{
    const PVOID handler = init_tampering_sys_call();
    HANDLE t = NULL;

    set_tampering_sys_call(
        (uintptr_t)GetProcAddress(GetModuleHandleW(L"NTDLL.dll"),
            "NtCreateThreadEx"),
        0
    );

    for (unsigned i = 0; i < 2; i++)
    {
        t = CreateThread(NULL, 0, test_thread, NULL, 0, NULL);
        if (t) WaitForSingleObject(t, INFINITE);
    }

    remove_tampering_sys_call(
        (uintptr_t)GetProcAddress(GetModuleHandleW(L"NTDLL.dll"),
            "NtCreateThreadEx"),
        0
    );

    un_init_tampering_sys_call(handler);
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          EOF                                         */
//////////////////////////////////////////////////////////////////////////////////////////
