CC=g++
CFLAGS=-m32
OBJDIR=.
BINDIR=.

all: $(BINDIR)/x86virt-disasm

$(OBJDIR)/%.o: %.cpp $(DEPS)
	$(CC) $(CFLAGS) -ggdb -c $< -o $@

$(BINDIR)/x86virt-disasm: $(OBJDIR)/main.o
	$(CC) -ggdb -m32 -o $(BINDIR)/x86virt-disasm $(OBJDIR)/main.o