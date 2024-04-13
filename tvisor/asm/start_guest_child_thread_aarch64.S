.global start_guest_child_thread

start_guest_child_thread:
    // Save x19 to the stack, and load the StartGuestChildThreadArg on it which is callee-saved.
    str x19, [sp, #-16]!
    mov x19, x5     // StartGuestChildThreadArg

    // start_guest_thread matches the argument layout of clone on aarch64.
    mov x8, 220 // == clone
    svc 0x0

    cmp x0, #0
    beq guest_start
    // Restore the original x19 and x20.
    ldr x19, [sp], #16
    ret

guest_start:
    // Set up the stack for the guest thread.
    mov x29, xzr
    ldr x0, [x19, #8] // sandbox_channel
    bl guest_thread_init

    // After the setup is done, we finally need to return to the guest child's execution.
    // First, we clear x0, which is the return value of clone for the child.
    mov x0, xzr

    // Next is to restore the original x19-x29. Before doing that, we need to move the entrypoint restored in x19
    // to a caller saved register, so that we can use x19 to restore the original x19.
    mov x1, x19  // StartGuestChildThreadArg
    ldr x2, [x1] // entrypoint

    // restore_regs on the StartGuestChildThreadArg starts at offset 16, so
    // restore the original x19-x30 from there (including link register x30 for vfork!).
    ldp x19, x20, [x1, #16]
    ldp x21, x22, [x1, #32]
    ldp x23, x24, [x1, #48]
    ldp x25, x26, [x1, #64]
    ldp x27, x28, [x1, #80]
    ldp x29, x30, [x1, #96]

    // Do not blr x2, as that would set the return address to the next instruction.
    br x2

    // This is unreachable. The guest should never return here.
    udf #0

.text
