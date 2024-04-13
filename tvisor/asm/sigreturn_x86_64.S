.global __sigreturn_x64
__sigreturn_x64:
    mov $15, %rax
    syscall
    ud2
.text
