//////////////////////////////////////////////////////////////////////////////////////////
/*                                       HWBP.c - @rad9800                              */
/*                                  Multi-thread safe hooking engine                    */
//////////////////////////////////////////////////////////////////////////////////////////
#include <Windows.h>
#include <tlhelp32.h>

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Macros                                      */
//////////////////////////////////////////////////////////////////////////////////////////

#define MALLOC( size ) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define FREE( adr ) HeapFree(GetProcessHeap(), 0, adr)

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Typedefs                                    */
//////////////////////////////////////////////////////////////////////////////////////////

/*
 * All callback functions must match this prototype.
 */
typedef void (WINAPI* exception_callback)(PEXCEPTION_POINTERS);

struct descriptor_entry
{
    /* Data */
    uintptr_t adr;
    unsigned pos;
    DWORD tid;
    exception_callback fun;


    struct descriptor_entry* next, * prev;
};

//////////////////////////////////////////////////////////////////////////////////////////
/*                                       Globals                                        */
//////////////////////////////////////////////////////////////////////////////////////////

CRITICAL_SECTION g_critical_section;
struct descriptor_entry* head = NULL;

//////////////////////////////////////////////////////////////////////////////////////////
/*                                 Function Definitions                                 */
//////////////////////////////////////////////////////////////////////////////////////////

/*
 * Function: set_hardware_breakpoint
 * ---------------------------------
 *  sets/removes a hardware breakpoint in the specified debug register for a specific
 *    function address
 *
 *    tid: thread id
 *    address: address of function to point a debug register towards
 *    pos: Dr[0-3]
 *    init: TRUE (Sets)/FALSE (Removes)
 */
void
set_hardware_breakpoint(
    const DWORD tid,
    const uintptr_t address,
    const UINT pos,
    const BOOL init
)
{
    CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE thd;

    if (tid == GetCurrentThreadId())
    {
        thd = GetCurrentThread();
    }
    else
    {
        thd = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    }

    GetThreadContext(thd, &context);

    if (init)
    {
        (&context.Dr0)[pos] = address;
        context.Dr7 &= ~(3ull << (16 + 4 * pos));
        context.Dr7 &= ~(3ull << (18 + 4 * pos));
        context.Dr7 |= 1ull << (2 * pos);
    }
    else
    {
        if ((&context.Dr0)[pos] == address)
        {
            context.Dr7 &= ~(1ull << (2 * pos));
            (&context.Dr0)[pos] = 0ull;
        }
    }

    SetThreadContext(thd, &context);

    if (thd != INVALID_HANDLE_VALUE) CloseHandle(thd);
}

/*
 * Function: set_hardware_breakpoint
 * ---------------------------------
 *  sets/removes a hardware breakpoint in the specified debug register for a specific
 *    function address
 *
 *    address: address of function to point a debug register towards
 *    pos: Dr[0-3]
 *    init: TRUE (Sets)/FALSE (Removes)
 *    tid: Thread ID (0 if to set on all threads)
 */
void
set_hardware_breakpoints(
    const uintptr_t address,
    const UINT pos,
    const BOOL init,
    const DWORD tid
)
{
    const DWORD pid = GetCurrentProcessId();
    const HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };

        if (Thread32First(h, &te)) {
            do {
                if ((te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                    sizeof(te.th32OwnerProcessID)) && te.th32OwnerProcessID == pid) {
                    if (tid != 0 && tid != te.th32ThreadID) {
                        continue;
                    }
                    set_hardware_breakpoint(
                        te.th32ThreadID,
                        address,
                        pos,
                        init
                    );

                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        CloseHandle(h);
    }
}

/* DLL related functions */

/*
 * Function: insert_descriptor_entry
 * ---------------------------------
 * Instantiates a hardware hook at the supplied address.
 *
 *    adr: address to hook
 *    pos: Dr[0-3]
 *    fun: callback function matching the exception_callback signature
 *    tid: Thread ID (if is 0, will apply hook to all threads)
 *
 */
void insert_descriptor_entry(
    const uintptr_t adr,
    const unsigned pos,
    const exception_callback fun,
    const DWORD tid
)
{
    struct descriptor_entry* new = MALLOC(sizeof(struct descriptor_entry));
    const unsigned idx = pos % 4;

    EnterCriticalSection(&g_critical_section);

    new->adr = adr;
    new->pos = idx;
    new->tid = tid;
    new->fun = fun;

    new->next = head;

    new->prev = NULL;

    if (head != NULL)
        head->prev = new;

    head = new;

    LeaveCriticalSection(&g_critical_section);

    set_hardware_breakpoints(
        adr,
        idx,
        TRUE,
        tid
    );
}

/*
 * Function: insert_descriptor_entry
 * ---------------------------------
 *  Removes the hardware breakpoint entry
 *
 *    adr: address to hook
 *    tid: Thread ID (if is 0, will apply hook to all threads)
 *         N.B. the tid must match the originally applied value
 *
 */
void delete_descriptor_entry(
    const uintptr_t adr,
    const DWORD tid
)
{
    struct descriptor_entry* temp;
    unsigned pos = 0;
    BOOL found = FALSE;

    EnterCriticalSection(&g_critical_section);

    temp = head;

    while (temp != NULL)
    {
        if (temp->adr == adr &&
            temp->tid == tid)
        {
            found = TRUE;

            pos = temp->pos;
            if (head == temp)
                head = temp->next;

            if (temp->next != NULL)
                temp->next->prev = temp->prev;

            if (temp->prev != NULL)
                temp->prev->next = temp->next;

            FREE(temp);
        }

        temp = temp->next;
    }

    LeaveCriticalSection(&g_critical_section);

    if (found)
    {
        set_hardware_breakpoint(
            tid,
            adr,
            pos,
            FALSE
        );
    }

}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                      Exception Handler                               */
//////////////////////////////////////////////////////////////////////////////////////////
/*
 * Function: exception_handler
 * -----------------------------------------
 *  hardware breakpoint exception handler required to deal with set debug registers.
 *  initiated by hardware_engine_init and removed by hardware_engine_stop
 *
 */
LONG WINAPI exception_handler(
    PEXCEPTION_POINTERS ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        struct descriptor_entry* temp;
        BOOL resolved = FALSE;

        EnterCriticalSection(&g_critical_section);
        temp = head;
        while (temp != NULL)
        {
            if (temp->adr == ExceptionInfo->ContextRecord->Rip)
            {
                if (temp->tid != 0 && temp->tid != GetCurrentThreadId())
                    continue;

                temp->fun(ExceptionInfo);
                resolved = TRUE;
            }

            temp = temp->next;
        }
        LeaveCriticalSection(&g_critical_section);

        if (resolved)
        {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * Function: hardware_engine_init
 * ------------------------------
 *  initializes the VEH and critical section
 *
 * returns: handler to the exception handler (can be removed with
 *          RemoveVectoredExceptionHandler.
 */
PVOID
hardware_engine_init(
    void
)
{
    const PVOID handler = AddVectoredExceptionHandler(1, exception_handler);
    InitializeCriticalSection(&g_critical_section);

    return handler;
}

/*
 * Function: hardware_engine_stop
 * ------------------------------
 *  Disables all currently set hardware breakpoints, and
 *  clears all the descriptor entries.
 *
 */
void
hardware_engine_stop(
    PVOID handler
)
{
    struct descriptor_entry* temp;

    EnterCriticalSection(&g_critical_section);

    temp = head;
    while (temp != NULL)
    {
        delete_descriptor_entry(temp->adr, temp->tid);
        temp = temp->next;
    }

    LeaveCriticalSection(&g_critical_section);

    if (handler != NULL) RemoveVectoredExceptionHandler(handler);

    DeleteCriticalSection(&g_critical_section);
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                       Callbacks                                      */
//////////////////////////////////////////////////////////////////////////////////////////

/*
 * Function: sleep_callback_test
 * -----------------------------
 *  Called by the exception handler after it is registered to the global DLL.
 *
 *    ExceptionInfo: Pointer to Exception Information (provided by VEH)
 *
 */
void sleep_callback_test(const PEXCEPTION_POINTERS ExceptionInfo)
{
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
    ExceptionInfo->ContextRecord->Rcx = 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Entry                                       */
//////////////////////////////////////////////////////////////////////////////////////////

int main()
{
    const PVOID handler = hardware_engine_init();
    struct descriptor_entry* temp;

    /* 0 - all threads / GetCurrentThreadId() */
    insert_descriptor_entry(&Sleep, 0, sleep_callback_test, 0);
    //insert_descriptor_entry(&Sleep, 0, sleep_callback_test, GetCurrentThreadId());

    Sleep(0xDEADBEEF);

    delete_descriptor_entry(&Sleep, 0);
    //delete_descriptor_entry(&Sleep, GetCurrentThreadId());

    hardware_engine_stop(handler);
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          EOF                                         */
//////////////////////////////////////////////////////////////////////////////////////////
