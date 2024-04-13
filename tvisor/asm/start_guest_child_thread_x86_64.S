.global start_guest_child_thread

// https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf

start_guest_child_thread:
    // In order to be able to use StartGuestChildThreadArg on both child and parent,
    // we have to save it in the callee-saved register r12.
    // So first we save r12 on the stack, then we can use it as a scratch register.
    pushq %r12
    // Then move the StartGuestChildThreadArg to r12.
    mov %r9, %r12

    // Do the system call:
    //   long clone(unsigned long flags, void *stack,
    //              int *parent_tid, int *child_tid,
    //              unsigned long tls);
    // which is different in that child_tid comes before tls.
    // so we have to swap them.
    //
    // But for system calls, the 4th argument is passed in r10, not rcx.
    // So, we have to move r8 to r10, and then move rcx to r8.
    mov %r8, %r10
    mov %rcx, %r8
    mov $56, %rax  // == clone
    syscall

    test %rax, %rax
    jz guest_start
    jl error
    // Pop the saved r12 from the stack.
    popq %r12
    ret

guest_start:
    xor %rbp, %rbp
    mov 8(%r12), %rdi // sandbox_channel
    call guest_thread_init

    // Move the StartGuestChildThreadArg on r12 to rax which can be freely used now.
    mov %r12, %rax

    // We have to restore the registers that are supposed to be preserved across system call.
    // These registers are: rbx, rbp, r12, r13, r14, r15.
    // See section 3.2.3 and A.2.1 of https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf
    //
    // We load the pointer to the restore_regs from the StartGuestChildThreadArg,
    // which is at offset 16 of the StartGuestChildThreadArg.
    // The offset in restore_regs is determined by sys::x86_64::mcontext_t::copy_restore_target_regs
    // Then we load the registers from the mcontext.
    mov 16(%rax), %rbx
    mov 24(%rax), %rbp
    mov 32(%rax), %r12
    mov 40(%rax), %r13
    mov 48(%rax), %r14
    mov 56(%rax), %r15
    mov 64(%rax), %r9

    // TODO: restore the return address for vfork.

    // Now ready to execute the guest child thread entrypoint.
    // rcx can be used as a scratch register.
    mov (%rax), %rcx // entrypoint
    // On child thread, the return value for clone is 0.
    xor %rax, %rax
    jmp *%rcx

error:
    ud2

.text
