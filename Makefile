VMLINUX = bpf/include/vmlinux.h
BIN_DIR = bin
PORG_NAME = msq-obsrv
BPF_PKG = pkg/bpf
GEN_GO_FILE = $(BPF_PKG)/$(PORG_NAME)_bpfeb.go

ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG := clang -I./bpf/include

SUDO ?= sudo

.PHONY: vmlinux
vmlinux: $(VMLINUX)
$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

.PHONY: build
build: $(VMLINUX) $(GEN_GO_FILE)
	go build .


.PHONY: clean
clean:
	rm $(VMLINUX)
	rm $(BIN_DIR)/*
	rm $(BPF_PKG)/$(PORG_NAME)*

.PHONY: bpf2go
bpf2go: $(GEN_GO_FILE)
$(GEN_GO_FILE):
	go generate ./...

%.o: bpf/%.c bpf/include/vmlinux.h
	$(CLANG) \
		-target bpf \
	-D __TARGET_ARCH_$(ARCH) \
		-Wall \
		-O2 -g -o $@ -c $<

$(BIN_DIR):
	mkdir -p bin

HOST=1
.PHONY: env
env:
	$(SUDO) scripts/env.sh $(HOST)
	$(SUDO) ip netns exec ext python3 -m http.server 8080

.PHONY: clean-env
clean-env:
	$(SUDO) scripts/clean.sh $(HOST)


N=1000000
C=1000
.PHONY: load
load:
	$(SUDO) scripts/run.sh $(HOST) $(N) $(C)
