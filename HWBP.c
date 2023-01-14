//////////////////////////////////////////////////////////////////////////////////////////
/*                                       HWBP.c - @rad9800                              */
/*                              Multi-thread safe x86/x64 hooking engine                */
//////////////////////////////////////////////////////////////////////////////////////////
#include <Windows.h>
#include <tlhelp32.h>

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Macros                                      */
//////////////////////////////////////////////////////////////////////////////////////////

#define MALLOC( size ) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define FREE( adr ) HeapFree(GetProcessHeap(), 0, adr)


#if defined(__x86_64__) || defined(_M_X64)
typedef void (__stdcall* exception_callback)(const PEXCEPTION_POINTERS);
#define EXCEPTION_CURRENT_IP(ei) (ei->ContextRecord->Rip)
#define EXCEPTION_FIRST_ARG(ei) (ei->ContextRecord->Rcx)
#define EXCEPTION_SECOND_ARG(ei) (ei->ContextRecord->Rdx)
#define EXCEPTION_THIRD_ARG(ei) (ei->ContextRecord->R8)
#define EXCEPTION_FOURTH_ARG(ei) (ei->ContextRecord->R9)
#define EXCEPTION_FIFTH_ARG(ei) *(PVOID*)(ei->ContextRecord-Rsp + sizeof(PVOID) * 5)
#define EXCEPTION_SIXTH_ARG(ei) *(PVOID*)(ei->ContextRecord-Rsp + sizeof(PVOID) * 6)
#define EXCEPTION_SEVENTH_ARG(ei) *(PVOID*)(ei->ContextRecord-Rsp + sizeof(PVOID) * 7)
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
typedef void (__cdecl* exception_callback)(const PEXCEPTION_POINTERS);
#define EXCEPTION_CURRENT_IP(ei) (ei->ContextRecord->Eip)
#define EXCEPTION_FIRST_ARG(ei) *(PVOID*)(ei->ContextRecord->Esp + sizeof(PVOID))
#define EXCEPTION_SECOND_ARG(ei) *(PVOID*)(ei->ContextRecord->Esp + sizeof(PVOID)*2)
#define EXCEPTION_THIRD_ARG(ei) *(PVOID*)(ei->ContextRecord->Esp + sizeof(PVOID)*3)
#define EXCEPTION_FOURTH_ARG(ei) *(PVOID*)(ei->ContextRecord->Esp + sizeof(PVOID)*4)
#define EXCEPTION_FIFTH_ARG(ei) *(PVOID*)(ei->ContextRecord->Esp + sizeof(PVOID)*5)
#define EXCEPTION_SIXTH_ARG(ei) *(PVOID*)(ei->ContextRecord->Esp + sizeof(PVOID)*6)
#define EXCEPTION_SEVENTH_ARG(ei) *(PVOID*)(ei->ContextRecord->Esp + sizeof(PVOID)*7)
#endif

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Typedefs                                    */
//////////////////////////////////////////////////////////////////////////////////////////

struct descriptor_entry
{
    PVOID adr;
    unsigned pos;
    DWORD tid;
    BOOL dis;
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
 *
 *    return:
 *      BOOL - TRUE/FALSE
 */
BOOL
set_hardware_breakpoint(
    const DWORD tid,
    const PVOID address,
    const UINT pos,
    const BOOL init
)
{
    HANDLE thd = INVALID_HANDLE_VALUE;
    BOOL ret = FALSE;

    do
    {
        CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

        if (tid == GetCurrentThreadId())
        {
            thd = GetCurrentThread();
        }
        else
        {
            thd = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        }

        if (thd == INVALID_HANDLE_VALUE)
            break;

        if (!GetThreadContext(thd, &context))
            break;

        if (init)
        {
            (PVOID)(&context.Dr0)[pos] = address;
            context.Dr7 &= ~(3ull << (16 + 4 * pos));
            context.Dr7 &= ~(3ull << (18 + 4 * pos));
            context.Dr7 |= 1ull << (2 * pos);
        }
        else
        {
            if ((PVOID)(&context.Dr0)[pos] == address)
            {
                context.Dr7 &= ~(1ull << (2 * pos));
                (&context.Dr0)[pos] = 0ull;
            }
        }

        if (!SetThreadContext(thd, &context))
            break;

        ret = TRUE;

    } while (FALSE);
    
    if (thd != INVALID_HANDLE_VALUE) CloseHandle(thd);

    return TRUE;
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
 *
 *    return:
 *      BOOL - TRUE/FALSE
 */
BOOL
set_hardware_breakpoints(
    const PVOID address,
    const UINT pos,
    const BOOL init,
    const DWORD tid
)
{
    const DWORD pid = GetCurrentProcessId();
    const HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (h == INVALID_HANDLE_VALUE)
        return FALSE;

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

    return TRUE;
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
 *    dis: Disable DR during callback (allows you to call original function)
 */
BOOL insert_descriptor_entry(
    const PVOID adr,
    const unsigned pos,
    const exception_callback fun,
    const DWORD tid,
    const BOOL dis
)
{
    const unsigned idx = pos % 4;
    struct descriptor_entry* new = MALLOC(sizeof(struct descriptor_entry));
    if (!new)
        return FALSE;

    EnterCriticalSection(&g_critical_section);

    new->adr = adr;
    new->pos = idx;
    new->tid = tid;
    new->fun = fun;
    new->dis = TRUE;

    new->next = head;

    new->prev = NULL;

    if (head != NULL)
        head->prev = new;

    head = new;

    LeaveCriticalSection(&g_critical_section);

    return set_hardware_breakpoints(
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
BOOL delete_descriptor_entry(
    const PVOID adr,
    const DWORD tid
)
{
    struct descriptor_entry* temp = NULL;
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
        return set_hardware_breakpoints(
            adr,
            pos,
            FALSE,
            tid
        );
    }

    return FALSE;
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
    const PEXCEPTION_POINTERS ExceptionInfo
)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        struct descriptor_entry* temp = NULL;
        BOOL resolved = FALSE;

        EnterCriticalSection(&g_critical_section);
        temp = head;
        while (temp != NULL)
        {
            if (temp->adr == (PVOID)EXCEPTION_CURRENT_IP(ExceptionInfo))
            {
                if (temp->tid != 0 && temp->tid != GetCurrentThreadId())
                    continue;
                //
                // We have found our node, now check if we need to disable current Dr
                //
                if (temp->dis)
                {
                    set_hardware_breakpoint(
                        GetCurrentThreadId(),
                        temp->adr,
                        temp->pos,
                        FALSE
                    );
                }

                temp->fun(ExceptionInfo);

                //
                // re-enable dr for our current thread
                //
                if (temp->dis)
                {
                    set_hardware_breakpoint(
                        GetCurrentThreadId(),
                        temp->adr,
                        temp->pos,
                        TRUE
                    );
                }

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
    struct descriptor_entry* temp = NULL;

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

void sleep_callback_test(const PEXCEPTION_POINTERS ExceptionInfo)
{
    Sleep(1000);
    EXCEPTION_FIRST_ARG(ExceptionInfo) = 0;
    ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          Entry                                       */
//////////////////////////////////////////////////////////////////////////////////////////

int main()
{
    const PVOID handler = hardware_engine_init();

    //
    // 0 to hook all threads 
    // GetCurrentThreadId() for current thread
    //
    insert_descriptor_entry(Sleep, 0, sleep_callback_test, 0, TRUE);
    //insert_descriptor_entry(Sleep, 0, sleep_callback_test, GetCurrentThreadId());

    Sleep(0xDEADBEEF);

    delete_descriptor_entry(Sleep, 0);
    //delete_descriptor_entry(Sleep, GetCurrentThreadId());

    hardware_engine_stop(handler);
}

//////////////////////////////////////////////////////////////////////////////////////////
/*                                          EOF                                         */
//////////////////////////////////////////////////////////////////////////////////////////
