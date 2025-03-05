# Custom Meterpreter Linux x64 TCP Stager Listener

This project is the side project when i analyze how the metasploit meterpreter payload works.

## requirements
```
keystone-engine
1. pip install keystone-engine
2. https://www.keystone-engine.org/download/ or macos https://formulae.brew.sh/formula/keystone
```

## Usage

```
# prepare for stage2 paylaod 
make shellcode.elf

# start a Fake metepreter handler 
make stager

# build stage1 payload
make  regenerate 
# or
make victim.elf

# let victim run 
./victim.elf
```

