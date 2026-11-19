section .data
    msg db "Welcome to network, Marbathara!", 10    ; Message + newline (10)
    msg_len equ $ - msg                 ; Calculate string length

    ; sockaddr_in6 struct (28 bytes total)
    sockaddr6:
        dw 10                           ; sin6_family: AF_INET6 (10 on Linux)
        dw 0x5c11                       ; sin6_port: Port 4444 in big-endian (0x115c swapped)
        dd 0                            ; sin6_flowinfo: 0
        dq 0, 0                         ; sin6_addr: :: (16 bytes of zeros = in6addr_any)
        dd 0                            ; sin6_scope_id: 0

section .text
    global _start

_start:
    ; 1. socket(AF_INET6=10, SOCK_STREAM=1, protocol=0)
    mov rax, 41                         ; syscall: sys_socket
    mov rdi, 10                         ; AF_INET6 (changed from 2)
    mov rsi, 1                          ; SOCK_STREAM (TCP)
    xor rdx, rdx                        ; protocol 0
    syscall
    mov r12, rax                        ; Save server socket FD in r12

    ; 2. bind(sockfd, &sockaddr6, 28)
    mov rax, 49                         ; syscall: sys_bind
    mov rdi, r12                        ; server socket FD
    mov rsi, sockaddr6                  ; pointer to sockaddr_in6 struct
    mov rdx, 28                         ; struct length (changed from 16 to 28 bytes)
    syscall

    ; 3. listen(sockfd, backlog=5)
    mov rax, 50                         ; syscall: sys_listen
    mov rdi, r12                        ; server socket FD
    mov rsi, 5                          ; backlog queue size
    syscall

    ; 4. accept(sockfd, NULL, NULL)
    mov rax, 43                         ; syscall: sys_accept
    mov rdi, r12                        ; server socket FD
    xor rsi, rsi                        ; NULL (ignore client addr)
    xor rdx, rdx                        ; NULL (ignore addr len)
    syscall
    mov r13, rax                        ; Save connected client FD in r13

    ; 5. write(client_fd, msg, msg_len)
    mov rax, 1                          ; syscall: sys_write
    mov rdi, r13                        ; client socket FD
    mov rsi, msg                        ; message buffer
    mov rdx, msg_len                    ; message length
    syscall

    ; 6. close(client_fd) & close(server_fd)
    mov rax, 3                          ; syscall: sys_close
    mov rdi, r13
    syscall

    mov rax, 3                          ; syscall: sys_close
    mov rdi, r12
    syscall

    ; 7. exit(0)
    mov rax, 60                         ; syscall: sys_exit
    xor rdi, rdi                        ; status 0
    syscall
    
