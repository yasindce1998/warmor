CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PHONY: all clean

all: execve_monitor.bpf.o openat_monitor.bpf.o connect_monitor.bpf.o

execve_monitor.bpf.o: execve_monitor.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c execve_monitor.bpf.c -o execve_monitor.bpf.o

openat_monitor.bpf.o: openat_monitor.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c openat_monitor.bpf.c -o openat_monitor.bpf.o

connect_monitor.bpf.o: connect_monitor.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c connect_monitor.bpf.c -o connect_monitor.bpf.o

clean:
	rm -f *.o
