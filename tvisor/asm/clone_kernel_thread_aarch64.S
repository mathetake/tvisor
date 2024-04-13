.global clone_kernel_thread

clone_kernel_thread:
    // Save x19 to the stack, and save clone_kernel_args in x19 which is a callee-saved register.
    str x19, [sp, #-16]!
    mov x19, x2

    // Clear the unnecessary args for cloning kernel.
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr

    // Create a new thread.
    mov x8, 220 // == clone
    svc 0x0

    cmp x0, #0
    beq cloned

    // Restore x19 from the stack.
    ldr x19, [sp], #16
    ret

cloned:
    mov x29, xzr
    mov x0, x19 // clone_kernel_args
    bl cloned_kernel_main
    // Unreachable.
    udf #0

.text
