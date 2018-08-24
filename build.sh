nasm -f elf32 decrypt.asm
g++ -m32 main.cpp decrypt.o -ludis86 -o x86virt-disassembler
