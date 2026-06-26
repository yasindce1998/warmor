# Makefile for eBPF-for-Windows programs
# Requires: clang, llvm, eBPF-for-Windows SDK

# Compiler settings
CLANG := clang
CFLAGS := -O2 -target bpf -c -g

# eBPF-for-Windows specific flags
# Adjust path based on eBPF-for-Windows SDK installation
EBPF_WINDOWS_SDK ?= C:/Program Files/ebpf-for-windows/sdk
EBPF_INCLUDES := -I"$(EBPF_WINDOWS_SDK)/include"

# Output directory
OUT_DIR := .
INSTALL_DIR := ../internal/platform/etw/programs

# Source files
PROCESS_SRC := process_monitor.bpf.c
FILE_SRC := file_monitor.bpf.c
NETWORK_SRC := network_monitor.bpf.c

# Object files (no .bpf infix — matches Go loader expectations)
PROCESS_OBJ := $(OUT_DIR)/process_monitor.o
FILE_OBJ := $(OUT_DIR)/file_monitor.o
NETWORK_OBJ := $(OUT_DIR)/network_monitor.o

# Default target
all: $(PROCESS_OBJ) $(FILE_OBJ) $(NETWORK_OBJ)

# Compile process monitor
$(PROCESS_OBJ): $(PROCESS_SRC)
	@echo "Compiling process monitor..."
	$(CLANG) $(CFLAGS) $(EBPF_INCLUDES) -o $@ $<

# Compile file monitor
$(FILE_OBJ): $(FILE_SRC)
	@echo "Compiling file monitor..."
	$(CLANG) $(CFLAGS) $(EBPF_INCLUDES) -o $@ $<

# Compile network monitor
$(NETWORK_OBJ): $(NETWORK_SRC)
	@echo "Compiling network monitor..."
	$(CLANG) $(CFLAGS) $(EBPF_INCLUDES) -o $@ $<

# Clean build artifacts
clean:
	rm -f $(PROCESS_OBJ) $(FILE_OBJ) $(NETWORK_OBJ)

# Install compiled programs to the Go package directory
install: all
	@mkdir -p $(INSTALL_DIR)
	cp $(PROCESS_OBJ) $(INSTALL_DIR)/
	cp $(FILE_OBJ) $(INSTALL_DIR)/
	cp $(NETWORK_OBJ) $(INSTALL_DIR)/
	@echo "Installed to $(INSTALL_DIR)"

# Check that the SDK path exists
check:
	@if [ ! -d "$(EBPF_WINDOWS_SDK)" ]; then \
		echo "ERROR: eBPF-for-Windows SDK not found at $(EBPF_WINDOWS_SDK)"; \
		echo "Install from: https://github.com/microsoft/ebpf-for-windows"; \
		exit 1; \
	fi
	@echo "SDK found at $(EBPF_WINDOWS_SDK)"

# Help
help:
	@echo "eBPF-for-Windows Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build all eBPF programs (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install programs to Go package"
	@echo "  check    - Verify SDK is installed"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Environment:"
	@echo "  EBPF_WINDOWS_SDK - SDK path (default: C:/Program Files/ebpf-for-windows/sdk)"

.PHONY: all clean install check help
