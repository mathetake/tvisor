.global start_guest_main_thread

start_guest_main_thread:
    // Save x19 and x20 in the stack.
    // Save x19 and x20 to the stack, and load args on them which are callee-saved.
    stp x19, x20, [sp, #-16]!
    ldr x19, [x5]     // entry_point
    ldr x20, [x5, #8] // sandbox_channel

    // start_guest_thread matches the argument layout of clone on aarch64.
    mov x8, 220 // == clone
    svc 0x0

    cmp x0, #0
    beq guest_start
    blt error
    // Restore the original x19 and x20.
    ldp x19, x20, [sp], #16
    ret

guest_start:
    mov x29, xzr
    mov x0, x20 // sandbox_channel
    bl guest_thread_init
    blr x19

error:
    udf #0

.text
