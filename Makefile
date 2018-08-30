CC=g++
CFLAGS=-m32
OBJDIR=obj
BINDIR=bin

all: $(BINDIR)/x86virt-disasm

$(OBJDIR)/%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -ggdb -c $< -o $@

$(OBJDIR)/%.o: %.asm
	nasm -f elf32 $< -o $@

$(BINDIR)/x86virt-disasm: $(OBJDIR)/main.o $(OBJDIR)/decrypt.o 
	$(CC) -ggdb -m32 -o $(BINDIR)/x86virt-disasm $(OBJDIR)/main.o $(OBJDIR)/decrypt.o -ludis86