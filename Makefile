CC	=  gcc -D__KERNEL__

CFLAGS = -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer -pipe 

ifdef CONFIG_M486
CFLAGS := $(CFLAGS) -m486
else
CFLAGS := $(CFLAGS) -m386
endif


all: minix_fs readaout readelf aouttoelf

aouttoelf: aouttoelf.c
	@$(CC) -m32 -o aouttoelf aouttoelf.c

readaout: readaout.c
	@$(CC) -m32 -o readaout readaout.c

readelf: readelf.c
	@$(CC) -m32 -o readelf readelf.c

minix_fs: minix_fs.c
	@$(CC) -m32 -o minix_fs minix_fs.c

clean:
	rm  minix_fs readaout readelf aouttoelf
