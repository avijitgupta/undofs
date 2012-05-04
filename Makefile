WRAPFS_VERSION="0.1"
EXTRA_CFLAGS += -DWRAPFS_VERSION=\"$(WRAPFS_VERSION)\" $(EXTRA) $(F1) $(F2)

obj-m := wrapfs.o
wrapfs-objs := dentry.o file.o inode.o main.o super.o lookup.o mmap.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall -o ioctl ioctl_user.c
clean:
	rm -f wrapfs.mod.o ioctl.o built-in.o dentry.o file.o inode.o main.o super.o lookup.o mmap.o  wrapfs.o wrapfs.ko wrapfs.mod.c modules.order Module.symvers
