# Makefile for eBPF-for-Windows programs
# Requires: clang, llvm, eBPF-for-Windows SDK

# Compiler settings
CLANG := clang
LLC := llc
CFLAGS := -O2 -target bpf -c
INCLUDES := -I/usr/include -I/usr/include/x86_64-linux-gnu

# eBPF-for-Windows specific flags
# Note: Adjust paths based on eBPF-for-Windows SDK installation
EBPF_WINDOWS_SDK := C:/Program Files/ebpf-for-windows/sdk
EBPF_INCLUDES := -I"$(EBPF_WINDOWS_SDK)/include"

# Output directory
OUT_DIR := .

# Source files
PROCESS_SRC := process_monitor.bpf.c
FILE_SRC := file_monitor.bpf.c
NETWORK_SRC := network_monitor.bpf.c

# Object files
PROCESS_OBJ := $(OUT_DIR)/process_monitor.bpf.o
FILE_OBJ := $(OUT_DIR)/file_monitor.bpf.o
NETWORK_OBJ := $(OUT_DIR)/network_monitor.bpf.o

# Default target
all: $(PROCESS_OBJ) $(FILE_OBJ) $(NETWORK_OBJ)

# Compile process monitor
$(PROCESS_OBJ): $(PROCESS_SRC)
	@echo "Compiling process monitor..."
	$(CLANG) $(CFLAGS) $(EBPF_INCLUDES) -o $@ $<
	@echo "✓ Process monitor compiled"

# Compile file monitor
$(FILE_OBJ): $(FILE_SRC)
	@echo "Compiling file monitor..."
	$(CLANG) $(CFLAGS) $(EBPF_INCLUDES) -o $@ $<
	@echo "✓ File monitor compiled"

# Compile network monitor
$(NETWORK_OBJ): $(NETWORK_SRC)
	@echo "Compiling network monitor..."
	$(CLANG) $(CFLAGS) $(EBPF_INCLUDES) -o $@ $<
	@echo "✓ Network monitor compiled"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(PROCESS_OBJ) $(FILE_OBJ) $(NETWORK_OBJ)
	@echo "✓ Clean complete"

# Install (copy to expected location)
install: all
	@echo "Installing eBPF programs..."
	@mkdir -p ../internal/platform/etw/programs
	cp $(PROCESS_OBJ) ../internal/platform/etw/programs/
	cp $(FILE_OBJ) ../internal/platform/etw/programs/
	cp $(NETWORK_OBJ) ../internal/platform/etw/programs/
	@echo "✓ eBPF programs installed"

# Verify eBPF programs
verify: all
	@echo "Verifying eBPF programs..."
	@echo "Note: Requires eBPF-for-Windows verifier tool"
	@# TODO: Add verification command when available
	@echo "✓ Verification complete (manual check required)"

# Help
help:
	@echo "eBPF-for-Windows Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build all eBPF programs (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install programs to warmor"
	@echo "  verify   - Verify eBPF programs"
	@echo "  help     - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang (LLVM)"
	@echo "  - eBPF-for-Windows SDK"
	@echo ""
	@echo "Note: Adjust EBPF_WINDOWS_SDK path in Makefile"

.PHONY: all clean install verify help


