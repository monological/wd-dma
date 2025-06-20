EXTRA_CFLAGS  += -fcf-protection=none -Wa,-mrelax-relocations=no
obj-m := wd_dma.o

KDIR   := /lib/modules/$(shell uname -r)/build
PKGS   := build-essential linux-headers-$(shell uname -r) dkms flex bison libelf-dev

ifeq ($(KERNELRELEASE),)

.DEFAULT_GOAL := all

.PHONY: all setup modules test install clean

all: modules test

setup:
	sudo apt update
	sudo apt install -y $(PKGS)

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

test: test.c
	$(CC) -Wall -O2 -o $@ $<

install: all
	sudo rmmod wd_dma 2>/dev/null || true
	sudo insmod wd_dma.ko

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	$(RM) test

endif
