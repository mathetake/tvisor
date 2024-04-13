.global _start
_start:
	mov %rsp, %rdi
	jmp   rust_start
.section .text
