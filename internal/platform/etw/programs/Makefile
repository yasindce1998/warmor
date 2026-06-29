# Makefile for warmor eBPF-for-Windows programs
# Requires: clang with BPF target support
#   Install: winget install LLVM.LLVM or download from https://releases.llvm.org/

CLANG   ?= clang
CFLAGS  = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I.
PROGRAMS = process_monitor.o file_monitor.o network_monitor.o

.PHONY: all clean install

all: $(PROGRAMS)

%.o: %.c warmor_common.h
	$(CLANG) $(CFLAGS) -c $< -o $@

# Install compiled objects to the default program directory
install: all
	@mkdir -p ../../../../bpf-windows 2>/dev/null || true
	cp $(PROGRAMS) ../../../../bpf-windows/

clean:
	rm -f $(PROGRAMS)
