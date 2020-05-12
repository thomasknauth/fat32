fat32: fat32.rs
	rustc $^

.PHONY: mount
mount:
	# hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount 128M
	hdiutil attach -imagekey diskimage-class=CRawDiskImage test.img
	# diskutil eraseDisk FAT32 NAME MBRFormat /dev/disk3

.PHONY: unmount
unmount:
	hdiutil unmount /Volumes/NAME

test.img:
	dd if=/dev/zero of=$@ bs=1m count=128
	hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount $@ > devnode
	diskutil eraseDisk FAT32 NAME MBRFormat $(shell cat devnode)
	hdiutil mount $(shell cat devnode)
	mkdir /Volumes/NAME/dir1
	mkdir /Volumes/NAME/dir2
	echo Hello, world! > /Volumes/NAME/f1
	echo Hello again, world! > /Volumes/NAME/dir1/f2
	hdiutil detach /Volumes/NAME

.PHONY: check
check: fat32
	./fat32

.PHONY: clean
clean:
	$(RM) devnode

.PHONY: distclean
distclean: clean
	$(RM) test.img
