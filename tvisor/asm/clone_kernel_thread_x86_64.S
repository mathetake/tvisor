.global clone_kernel_thread

// https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f
clone_kernel_thread:
    // Save the current value on rbx to restore it later.
    pushq %rbx
    // Save clone_kernel_args in a callee-saved register.
    mov %rdx, %rbx

    // Clear the unnecessary args for cloning kernel.
    xor %rdx, %rdx
    xor %rcx, %rcx
    xor %r8, %r8

    mov $56, %rax  // == clone
    syscall

    test %rax, %rax
    jz cloned
    jl error

    // Restore the saved value on rbx.
    popq %rbx
    ret

cloned:
    mov %rbx, %rdi // clone_kernel_args
    xor %rbp, %rbp
    call cloned_kernel_main

error:
    ud2

.text
