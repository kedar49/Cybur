MODULE=cybur
PWD := $(shell pwd)
KERNELRELEASE := $(shell uname -r)
KDIR := /lib/modules/${KERNELRELEASE}/build
MDIR := /lib/modules/${KERNELRELEASE}
obj-m := ${MODULE}.o
${MODULE}-objs := main.o dhcp.o

# Specify gcc as the compiler and add the -std=gnu99 flag
CC := gcc
EXTRA_CFLAGS := -std=gnu99

all:
	make -C ${KDIR} M=${PWD} CC=${CC} EXTRA_CFLAGS="${EXTRA_CFLAGS}" modules
	rm -r -f *.mod.c .*.cmd *.symvers *.o

install:
	sudo insmod ${MODULE}.ko

remove:
	sudo rmmod ${MODULE}

clean:
	make -C ${KDIR} M=${PWD} clean
