OUTPUT 		:= 	$(abspath .output)
VMLINUX 	:=  $(OUTPUT)/vmlinux
SKEL		:=  $(OUTPUT)/skel

.PHONY: all
all: bpfobj skel userspace


$(OUTPUT) $(OUTPUT)/vmlinux $(OUTPUT)/skel:
	mkdir -p $@

vmlinux: $(OUTPUT)/vmlinux
	/usr/sbin/bpftool btf dump -B /sys/kernel/btf/vmlinux file /sys/kernel/btf/vmlinux format c > src/ebpf/vmlinux.h

bpfobj: $(OUTPUT)
	clang -O2 -g -c -Wall -target bpf src/ebpf/beevmdr.bpf.c -o $(OUTPUT)/beevmdr.bpf.o -D__TARGET_ARCH_x86 -mcpu=v2

bpfobj-rs: $(OUTPUT)
	clang -O2 -g -c -Wall -target bpf src/ebpf/beevmdr.bpf.c -o src/ebpf/beevmdr.bpf.o -D__TARGET_ARCH_x86 -mcpu=v2

skel: $(OUTPUT)/skel
	/usr/sbin/bpftool gen skeleton $(OUTPUT)/beevmdr.bpf.o > $(SKEL)/beevmdr.skel.h

userspace:
	mkdir -p build
	gcc src/beevmdr.c -I $(SKEL) -o build/beevmdr -lelf -lz -lbpf -ljansson

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp build/beevmdr $(DESTDIR)/usr/bin/beevmdr

clean:
	rm -rf $(OUTPUT)