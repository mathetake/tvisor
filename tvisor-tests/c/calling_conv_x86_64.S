.global _start

.section .text
_start:
    // Save initial values of registers R12 to R15, RBX, RBP
    mov $0x1212, %r12
    mov $0x1313, %r13
    mov $0x1414, %r14
    mov $0x1515, %r15
    mov $0x1616, %rbx
    mov $0x1717, %rbp

    // Perform the system call (getuid)
    mov $102, %rax // syscall number for getuid in x86_64
    syscall

    // Compare the values of registers R12 to R15, RBX, RBP with initial values
    cmp $0x1212, %r12
    jne error_exit
    cmp $0x1313, %r13
    jne error_exit
    cmp $0x1414, %r14
    jne error_exit
    cmp $0x1515, %r15
    jne error_exit
    cmp $0x1616, %rbx
    jne error_exit
    cmp $0x1717, %rbp
    jne error_exit

    // If all values match, exit with code 0
    mov $231, %rax // syscall number for exit in x86_64
    xor %rdi, %rdi // exit code 0
    syscall

error_exit:
    // If values do not match, exit with code 1
    mov $231, %rax // syscall number for exit in x86_64
    mov $1, %rdi // exit code 1
    syscall
