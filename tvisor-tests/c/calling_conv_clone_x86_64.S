.global _start

_start:
    # Save initial values of registers R12 to R15, RBX, RBP.
    movq $1, %r12
    movq $2, %r13
    movq $3, %r14
    movq $4, %r15
    movq $5, %rbx
    movq $6, %rbp

    # Set up the arguments to clone syscall.
    movq $0x10f00, %rdi # CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
    leaq stack_buf(%rip), %rsi # Set a valid stack pointer.
    addq $0x10000, %rsi
    xorq %rdx, %rdx # We don't care.
    xorq %r10, %r10 # We don't care.
    xorq %r8, %r8   # We don't care.

    movq $56, %rax # syscall number for clone in x86-64
    syscall

    # Compare the values of registers R12 to R15, RBX, RBP with initial values.
    cmpq $1, %r12
    jne error_exit
    cmpq $2, %r13
    jne error_exit
    cmpq $3, %r14
    jne error_exit
    cmpq $4, %r15
    jne error_exit
    cmpq $5, %rbx
    jne error_exit
    cmpq $6, %rbp
    jne error_exit

    # Check if we are in the child thread.
    test %rax, %rax
    je exit_child
    js error_exit

    # Otherwise, we are in the parent thread.
    # Wait for the child thread to exit.
wait_loop:
    movq sync_flag(%rip), %rax
    testq %rax, %rax
    jz wait_loop  # If sync_flag is 0, keep waiting

    # Print a message to indicate that the parent is done.
    movq $1, %rdi  # stdout
    leaq parent_thread_msg(%rip), %rsi
    movq $parent_thread_msg_end - parent_thread_msg, %rdx
    movq $1, %rax # syscall number for write in x86-64
    syscall

    movq $231, %rax # syscall number for exit_group in x86-64
    xorq %rdi, %rdi # exit code 0
    syscall
    ud2

error_exit:
    # If values do not match, exit with code 1.
    movq $231, %rax # syscall number for exit_group in x86-64
    movq $1, %rdi # exit code 1
    syscall

exit_child:
    # Print a message to indicate that the child is done.
    movq $1, %rdi  # stdout
    leaq child_thread_msg(%rip), %rsi
    movq $child_thread_msg_end - child_thread_msg, %rdx
    movq $1, %rax # syscall number for write in x86-64
    syscall

    # Set sync_flag to 1 to indicate that we are done.
    movq $1, %rax
    movq %rax, sync_flag(%rip)

    # After setting sync_flag, we should be in an infinite loop and let the parent thread exit.
infinite_loop:
    jmp infinite_loop

.section .data
child_thread_msg: .ascii "Child Thread Done\n"
child_thread_msg_end:
parent_thread_msg: .ascii "Parent Thread Done\n"
parent_thread_msg_end:

sync_flag: .quad 0

.section .bss
.align 16
stack_buf: .space 0x10000
