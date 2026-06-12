CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PHONY: all clean

all: monitors lsm

.PHONY: monitors lsm

monitors: execve_monitor.bpf.o openat_monitor.bpf.o connect_monitor.bpf.o

lsm: lsm_exec.bpf.o lsm_file.bpf.o lsm_connect.bpf.o

execve_monitor.bpf.o: execve_monitor.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c execve_monitor.bpf.c -o execve_monitor.bpf.o

openat_monitor.bpf.o: openat_monitor.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c openat_monitor.bpf.c -o openat_monitor.bpf.o

connect_monitor.bpf.o: connect_monitor.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c connect_monitor.bpf.c -o connect_monitor.bpf.o

lsm_exec.bpf.o: lsm_exec.bpf.c warmor_lsm.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c lsm_exec.bpf.c -o lsm_exec.bpf.o

lsm_file.bpf.o: lsm_file.bpf.c warmor_lsm.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c lsm_file.bpf.c -o lsm_file.bpf.o

lsm_connect.bpf.o: lsm_connect.bpf.c warmor_lsm.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c lsm_connect.bpf.c -o lsm_connect.bpf.o

clean:
	rm -f *.o
