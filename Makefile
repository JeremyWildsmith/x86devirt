CC=g++
CFLAGS=-m32

all: x86virt-disasm

%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -ggdb -c $< -o $@

%.o: %.asm
	nasm -f elf32 $<

x86virt-disasm: main.o decrypt.o 
	$(CC) -ggdb -m32 -o x86virt-disasm main.o decrypt.o -ludis86