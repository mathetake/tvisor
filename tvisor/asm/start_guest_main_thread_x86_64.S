.global start_guest_main_thread

// https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf

start_guest_main_thread:
    // Save the args in callee-saved registers.
    // https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f
    mov (%r9), %rbx   // entry_point
    mov 8(%r9), %r12  // sandbox_channel

    // Do the system call:
    //   long clone(unsigned long flags, void *stack,
    //              int *parent_tid, int *child_tid,
    //              unsigned long tls);
    // which is different in that child_tid comes before tls.
    // so we have to swap them (rcx<>r8) by using rax as a temporary.
    mov %rcx, %rax
    mov %r8, %rcx
    mov %rax, %rcx
    mov $56, %rax  // == clone
    syscall

    test %rax, %rax
    jz guest_start
    jl error
    ret

guest_start:
    xor %rbp, %rbp
    mov %r12, %rdi // sandbox_channel
    call guest_thread_init
    xor %rbp, %rbp
    jmp *%rbx

error:
    ud2

.text
