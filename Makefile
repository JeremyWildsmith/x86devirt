CC=g++
CFLAGS=-m32

all: x86virt-disasm

%.o: %.cpp %.h
	$(CC) $(CFLAGS) -ggdb -c $< -o $@

x86virt-disasm: main.o VmInfo.o VmReg.o VmJmp.o
	$(CC) -ggdb -m32 -o x86virt-disasm main.o VmInfo.o VmReg.o VmJmp.o -ludis86 