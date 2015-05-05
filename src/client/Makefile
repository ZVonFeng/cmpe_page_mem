KBUILD_CFLAGS += -w

obj-m += netlinkKernel.o

all:
		make -w -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
