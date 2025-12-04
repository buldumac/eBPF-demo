# ============================
# Colors
# ============================
RESET  = \033[0m
GREEN  = \033[32m
BLUE   = \033[34m
YELLOW = \033[33m
CYAN   = \033[36m

# ============================
# Files
# ============================
BPF_SRC      = monitor.bpf.c
BPF_OBJ      = monitor.bpf.o
BPF_SKEL     = monitor.skel.h

LOADER_SRC   = bpf-loader.c
LOADER_BIN   = loader

DEMO_SRC     = suspicious_demo.c
DEMO_BIN     = suspicious_demo

# ============================
# Utility: print + run
# ============================
define run
	@echo "$(CYAN)$1$(RESET)"
	@$1
endef

# ============================
# Named: run loader
# ============================
COMM ?=

run-loader: $(LOADER_BIN)
	@echo "$(BLUE)[RUN] Executing loader$(RESET)"
	@if [ -n "$(COMM)" ]; then \
		echo "$(CYAN)./loader --comm $(COMM)$(RESET)"; \
		./loader --comm $(COMM); \
	else \
		echo "$(CYAN)./loader$(RESET)"; \
		./loader; \
	fi

# ============================
# Default target (same as build-all)
# ============================
all: build-all

# ============================
# Named target: build everything
# ============================
build-all: build-bpf build-skel build-loader build-demo
	@echo "$(GREEN)[DONE] All targets built successfully$(RESET)"

# ============================
# Generate vmlinux.h
# ============================
gen-vmlinux:
	@echo "$(BLUE)[BPF] Generating vmlinux.h$(RESET)"
	$(call run, bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h)


# ============================
# Named: build BPF object
# ============================
build-bpf: $(BPF_OBJ)
	@echo "$(GREEN)[OK] Built $(BPF_OBJ)$(RESET)"

# Actual rule
$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	@echo "$(BLUE)[BPF] Building $(BPF_OBJ)$(RESET)"
	$(call run, clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c $(BPF_SRC) -o $(BPF_OBJ))


# ============================
# Named: build skeleton
# ============================
build-skel: $(BPF_SKEL)
	@echo "$(GREEN)[OK] Generated $(BPF_SKEL)$(RESET)"

# Actual rule
$(BPF_SKEL): $(BPF_OBJ)
	@echo "$(BLUE)[BPF] Generating skeleton $(BPF_SKEL)$(RESET)"
	$(call run, bpftool gen skeleton $(BPF_OBJ) > $(BPF_SKEL))


# ============================
# Named: build loader
# ============================
build-loader: $(LOADER_BIN)
	@echo "$(GREEN)[OK] Built $(LOADER_BIN)$(RESET)"

# Actual rule
$(LOADER_BIN): $(LOADER_SRC) $(BPF_SKEL)
	@echo "$(BLUE)[USER] Building loader$(RESET)"
	$(call run, clang -O2 -g $(LOADER_SRC) -o $(LOADER_BIN) -I. -lbpf -lelf -lz)


# ============================
# Named: build demo program
# ============================
build-demo: $(DEMO_BIN)
	@echo "$(GREEN)[OK] Built $(DEMO_BIN)$(RESET)"

# Actual rule
$(DEMO_BIN): $(DEMO_SRC)
	@echo "$(BLUE)[USER] Building suspicious_demo$(RESET)"
	$(call run, gcc -O2 -Wall $(DEMO_SRC) -o $(DEMO_BIN))


# ============================
# Clean
# ============================
clean:
	@echo "$(YELLOW)[CLEAN] Removing build artifacts$(RESET)"
	$(call run, rm -f $(BPF_OBJ) $(BPF_SKEL) $(LOADER_BIN) $(DEMO_BIN) vmlinux.h)

.PHONY: all build-all gen-vmlinux build-bpf build-skel build-loader build-demo clean
