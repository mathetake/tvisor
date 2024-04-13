.global _start

_start:
    // Save initial values of registers X19 to X29.
    mov x19, 1
    mov x20, 2
    mov x21, 3
    mov x22, 4
    mov x23, 5
    mov x24, 6
    mov x25, 7
    mov x26, 8
    mov x27, 9
    mov x28, 10
    mov x29, 11

    // Perform the system call (getuid).
    mov x8, #174 // syscall number for getuid in AArch64
    svc #0

    // Compare the values of registers X19 to X29 with initial values.
    cmp x19, 1
    b.ne error_exit
    cmp x20, 2
    b.ne error_exit
    cmp x21, 3
    b.ne error_exit
    cmp x22, 4
    b.ne error_exit
    cmp x23, 5
    b.ne error_exit
    cmp x24, 6
    b.ne error_exit
    cmp x25, 7
    b.ne error_exit
    cmp x26, 8
    b.ne error_exit
    cmp x27, 9
    b.ne error_exit
    cmp x28, 10
    b.ne error_exit
    cmp x29, 11
    b.ne error_exit

    // If all values match, exit with code 0.
    mov x8, #94 // syscall number for exit in AArch64
    mov x0, #0  // exit code 0
    svc #0

error_exit:
    // If values do not match, exit with code 1.
    mov x8, #93 // syscall number for exit in AArch64
    mov x0, #1  // exit code 1
    svc #0

.text
