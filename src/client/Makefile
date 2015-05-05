Just run "make", then "gcc netlinkUser.c -o netlinkUser", then "sudo insmod netlinkKernel.ko", then when you run "./netlinkUser" you should see that a message was sent to the kernel module and a reply was received by the user space application. Running "dmesg" in the terminal after you will see the debug messages printed by the kernel module.Just run "make", then "gcc netlinkUser.c -o netlinkUser", then "sudo insmod netlinkKernel.ko", then when you run "./netlinkUser" you should see that a message was sent to the kernel module and a reply was received by the user space application. Running "dmesg" in the terminal after you will see the debug messages printed by the kernel module.KBUILD_CFLAGS += -w

obj-m += netlinkKernel.o

all:
		make -w -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
