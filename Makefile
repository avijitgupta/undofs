WRAPFS_VERSION="0.1"
EXTRA_CFLAGS += -DWRAPFS_VERSION=\"$(WRAPFS_VERSION)\" $(EXTRA)

obj-m := wrapfs.o 
wrapfs-objs := dentry.o file.o inode.o main.o super.o lookup.o mmap.o 
#EXTRA_CFLAGS=-DWRAPFS_CRYPTO
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	rm -f dentry.o file.o inode.o main.o super.o lookup.o mmap.o
