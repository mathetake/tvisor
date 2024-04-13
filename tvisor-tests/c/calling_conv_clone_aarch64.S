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

    // Set up the arguments to clone syscall.
    movz x0, 0x0f00 // CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
    movk x0, 0x1, lsl 16
    adr x1, stack_buf // Set a valid stack pointer.
    add x1, x1, 0x100000
    mov x2, #0 // We don't care.
    mov x3, #0 // We don't care.
    mov x4, #0 // We don't care.

    mov x8, 220 // == clone
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

    // Check if we are in the child thread.
    cmp x0, #0
    beq exit_child
    blt error_exit

    // Otherwise, we are in the parent thread.
    // Wait for the child thread to exit.
wait_loop:
    adr x1, sync_flag
    ldr w0, [x1]
    cbz w0, wait_loop  // If sync_flag is 0, keep waiting

    // Print a message to indicate that the parent is done.
    mov x0, #1  // stdout
    adr x1, parent_thread_msg
    mov x2, #parent_thread_msg_end - parent_thread_msg
    mov x8, #64 // syscall number for write in AArch64
    svc #0

    mov x8, #94 // syscall number for exit in AArch64
    mov x0, #0  // exit code 0
    svc #0

error_exit:
    // If values do not match, exit with code 1.
    mov x8, #94 // syscall number for exitgroup in AArch64
    mov x0, x15
    svc #0

exit_child:
    // Print a message to indicate that the child is done.
    mov x0, #1  // stdout
    adr x1, child_thread_msg
    mov x2, #child_thread_msg_end - child_thread_msg
    mov x8, #64 // syscall number for write in AArch64
    svc #0

    // Set sync_flag to 1 to indicate that we are done.
    mov w0, #1
    adr x1, sync_flag
    str w0, [x1]
    // After setting sync_flag, we should be in an infinite loop and let the parent thread exit.
infinite_loop:
    b infinite_loop

.text

.data
child_thread_msg: .ascii "Child Thread Done\n"
child_thread_msg_end:
parent_thread_msg: .ascii "Parent Thread Done\n"
parent_thread_msg_end:

sync_flag: .word 0

.bss
.align 16
stack_buf: .space 0x100000
