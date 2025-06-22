BITS 64
org 0x0

section .text
global _start

_start:
    mov rdi, 0x405014        ; pointer to "/bin/ping"
    mov rsi, 0x40502e        ; pointer to argv[]
    xor rdx, rdx             ; envp = NULL
    mov rax, 59              ; execve syscall
    syscall

section .data
cmd:    db "/bin/ping", 0
arg1:   db "-c", 0
arg2:   db "1", 0
arg3:   db "google.com", 0

argv:   dq 0x405014          ; argv[0] = &cmd
        dq 0x40501e          ; argv[1] = &arg1
        dq 0x405021          ; argv[2] = &arg2
        dq 0x405023          ; argv[3] = &arg3
        dq 0                 ; argv[4] = NULL
