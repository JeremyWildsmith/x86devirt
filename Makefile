CC=g++
CFLAGS=-m32


%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.asm
	nasm -f elf32 $<

x86virt-disasm: main.o decrypt.o 
	$(CC) -m32 -o x86virt-disasm main.o decrypt.o -ludis86